# VOLPAROSSA v1 implementation status

This is the repository's source of truth for implementation progress. A checked item means the repository contains the implementation and its stated verification has passed. Architecture documents, interfaces, disabled tests, mocks, simulations, and single-path fallbacks do **not** satisfy dataplane requirements.

Last updated: 2026-09-05

## Current live integration checkpoint

The detailed historical checklist below has not yet been reconciled with the complete
vertical runtime. It must not be read as a current measurement of elapsed work.
The retained [Debian 13 KVM datapath run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33972373384)
at `0075033e` passed A01--A07 and A15. A07 completed its 4 MiB HTTP/3 request and
32 MiB response after one relay was physically removed, with matching application hashes,
data on both paths before removal, data on the surviving path afterwards, and zero direct
Client--Exit packets. The run then stopped at `A08_ALLOWED_DNS_UDP_NOT_PROVEN`:
the generated Python DNS client lacked a shebang and was interpreted as shell code.
The corrected [rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/33975821992)
at `aaa44d60` stopped earlier at `A01_BOOTSTRAP1_ADVERTISEMENT_STALLED`: the new discovery
scheduler suppressed refreshing an unexpired advertisement after its Relay restarted.
Provider-triggered refresh is restored. The next
[datapath run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33979920940) at `0ae30c88`
again passed A01--A07 and A15, confirming discovery restart recovery. It reached A08 but still
stopped at `A08_ALLOWED_DNS_UDP_NOT_PROVEN`: the DNS client produced no response before its
deadline, although the Exit's own resolver returned the permitted fixture address. This is a
DNS integration failure in that revision, not a successful A08 result.
The cause is now corrected in the helper: UDP DNS uses TPROXY so the receiving agent keeps
the original resolver address and port 53; TCP DNS retains REDIRECT with `SO_ORIGINAL_DST`.
The real disposable-veth ingress smoke passed with exact DNS destination/reply-source metadata
and a subsequent datagram while the reply descriptor remained live. The
[next complete datapath run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33982369167)
at `9da11b81` again passed A01--A07 and A15. Its A08 DNS queries over **both UDP and TCP**
returned the exact allowed address `47.163.4.2` from `9.9.9.9:53`, and the permitted TLS 1.3
flow transferred 1 MiB with matching hashes and the exact Exit source. A08 nevertheless
remained failed because the fixture compared total completion-event counts across a rotating
400-record log snapshot: a previous event had disappeared when the new event arrived.
The fixture now measures exact events newer than its pre-request timestamp, retaining the
same bounded log window and all payload/source checks. The
[corrected datapath run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33984428352)
at `7a9ef998` **passed A01--A10 and A15**, including both DNS transports, allowed TLS,
all five A09 policy denials and both A10 ECH/unverifiable denials. It stopped at
`PRIVACY_CAPTURE_INCOMPLETE` because the Relay1 observer exited during A07's deliberate
link-down. A11--A13 remain unfinalized and A14 was not executed; cleanup completed with zero
owned objects and unchanged host-state hashes. A passing all-A01--A15 sequence is still required.
Both [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/33982300867) and
[CodeQL](https://github.com/VOLPAROSSA/volparossa/actions/runs/33982298530) passed at `9da11b81`.
Retained captures also exposed an A11 observer failure during A07's intentional Relay link-down.
The observer now reports that explicitly marked downtime and survives it; an actual isolated
veth packet-socket down/up check passes. The
[observer-fix run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33985404938)
at `88460c29` retained both Relay reports through the intentional failure, but stopped at A11.
Its bounded header-only tuple diagnostics identify the unexpected packets as discovery UDP
port 41000 attempts to non-neighbor private fixture addresses, not Internet-destination
payloads. Private-literal discovery admission and a behaviour-wide pre-dial gate now require
an address on an active directly attached local subnet, including Kademlia/mDNS-supplied
alternatives. Four focused scope checks (real disposable IPv4/ULA veth and link-down included),
five existing Identify/lineage checks and strict discovery Clippy pass. Mixed explicit dial
lists containing an ineligible private address are rejected as a whole. This is dial eligibility,
not a substitute for exact authenticated/helper route provenance. The zero-unexpected-packet
acceptance rule is unchanged. The [subsequent run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33988489921)
at `512fb180` traversed the privacy gates and reached A14, where it stopped at
`A14_OWNED_INVENTORY_INCOMPLETE`. Its failure handler also tried to aggregate an absent optional
A14 artifact, preventing the final report and individual evidence export. Therefore the runner
log alone is not a finalized A01--A13 pass. The crash fixture must establish an actual live
application route (completed probes are correctly retired), and failure reporting must retain
the already collected evidence. A passing all-A01--A15 report remains outstanding.
`0075033e` also passed
[Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/33972360525) and
[CodeQL](https://github.com/VOLPAROSSA/volparossa/actions/runs/33972358060).
This is partial evidence, not an all-A01--A15 alpha pass.

The current A07 correction gives a browser flow an explicit signature bounded by its
route, manifest and protocol lifetime, rather than the unrelated 60-second ingress
token. Expired or idle Exit browser flows are retired independently of other flows
sharing the same native connection. The live A07 result above verifies this correction;
it is not evidence for the separate combined-role or local-link extensions.

## Reciprocal participation revision (2026-09-05)

The user changed production participation from optional contribution to mandatory reciprocity:
any consuming Client must also offer Relay service and, when it has its own usable Internet
uplink, Exit service. The later same-day clarification permits a node without its own uplink
to contribute direct links and forwarding instead; it must not advertise fictitious Internet
egress. Installation is dormant; explicit
configuration enables contribution with nonzero capacity and the existing policy prerequisites.
All nodes use the same software. Development fixtures may still isolate roles to test boundaries.

- [x] Production config rejects client-only consumption; the default config is dormant.
- [x] Explicit `network.uplink` capability declaration: `local_only` permits Client + Relay
  configuration without fabricated ASN/public origin, and forbids Exit mode. This is config
  validation, not runtime connectivity proof or automatic uplink detection.
- [x] CLI/wire/agent honor Client disable; dormant Connect is rejected before route work.
- [x] One packaged node supervises separate immutable native Client and Exit workers/sockets.
- [x] Local Client candidate/provenance state is separate from Relay forwarding and Exit incoming
  Relay authority for other clients. Native Permit forwarding carries the control Relay's exact
  signed self-advertisement on the upstream-only hop; the Exit verifies it against the signed
  actor and authenticated connection without depending on its own Client candidate cache.
  The original Client-signed request is unchanged. Provider scheduling retains forwarded-only Exit choices
  in a homogeneous combined-role candidate pool.
- [x] Live reciprocal single-path QUIC MASQUE UDP proof: four unchanged participant daemons
  consume concurrently; three simultaneously serve as Client, Relay and policy-limited Exit
  in the observed path assignment. This does not claim combined-role TCP/MPQUIC load coverage.

Verification for the initial combined-role implementation: 369 agent library tests, 18 config tests, the Client
wire/CLI cases, strict Clippy for the changed Rust packages, and the combined native launcher
functional smoke passed locally. This does not substitute for the unchecked live datapath proof.
The capability declaration passed all 20 config tests and strict config/agent Clippy; focused
UDP path projection checks verify that general UDP reports one live native context without
claiming an MPQUIC path count. Local-only consumers retain the same forwarded-only Exit
candidate partition as consumers offering all three roles.
The disposable `reciprocity` scenario now starts four simultaneous participant flows and
separately verifies application hashes, selected WireGuard legs, exit source addresses and
unchanged agent processes. Its script/evidence-parser checks pass. The first
[live attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33976891461) at `27a4e73`
stopped at `RECIPROCITY_NEIGHBOR_DISCOVERY_UNAVAILABLE` before application traffic; all four
participants enabled all roles, but the signed candidate pool was incomplete. Startup partitioning
now waits for a viable provider pool across completed queries, preserving known neighboring
Relay contacts. The [next reciprocal run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33979922348)
at `0ae30c88` passed neighbor discovery but stopped at `RECIPROCITY_NATIVE_ROUTE_UNAVAILABLE`.
Kernel-originated Relay/Exit WireGuard outer packets lacked the Client-ingress bypass mark;
all four WireGuard roles now receive that mark. Failed Client native probes also used an
all-owned cleanup fallback that could destroy other roles' contexts: a destruction-only exact
context authority now survives consuming protocol joins, with no broad fallback in route setup.
These fixes have focused coverage. The live
[rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/33982372708) at `9da11b81`
now **passes**: four simultaneous application flows, 3.178 seconds of observed echo overlap,
matching request/response hashes and selected Exit sources, both WireGuard legs, three exact
same-daemon Client+Relay+Exit witnesses, zero direct Client--Exit packets/plaintext leaks and
complete cleanup with unchanged host-state hashes. It is the scoped reciprocal UDP proof,
not an A01--A15 or radio/aggregation result.
The failed KVM runs completely cleaned their owned state and retained unchanged host-state hashes.
The `27a4e73` [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33976851986) passed.
At `0ae30c88`, CodeQL passed but Quality found one stale exact-schema assertion for the new
`ObservationNetworkPrefix.scope` field. The strict assertion now includes tag 3, without
removing its field-count check.
The workflow defaults to `datapath` (all A01--A15 without package/release work); `alpha` retains
the additional package checks, and `reciprocity` emits only its own clearly scoped report.
The historical scorecard below predates the vertical runtime and this participation revision;
do not use its old percentage as a current completion estimate.

Development priority: integrate complete executable functionality and agreed ideas first.
During this phase use compilation and focused functional checks; defer additional release
hardening, exhaustive repeated regression runs, optimization and polish. Real datapaths,
route-specific privacy/policy enforcement and disposable-network cleanup remain functional
requirements, never labels that can be satisfied by mocks or configuration alone.

## Direct-link network extension (agreed 2026-09-05)

The functional-development target now includes direct Ethernet and Wi-Fi peer links alongside
Internet underlays, Internet access for a node without its own uplink through reachable
contributors, and parallel use of independently useful local and Internet paths. Contribution
is mandatory according to available capabilities. Owner traffic takes priority over contributed
traffic; spare capacity must be measured and enforced, not inferred from configured limits alone.

- [ ] Local on-link authenticated discovery and two-leg datapaths without a client default route.
- [ ] Per-path underlay/interface binding for simultaneous local and Internet paths.
- [ ] Driver-supported direct Wi-Fi link setup, teardown and real-radio transfer proof.
- [ ] Measured spare-capacity sharing with owner-priority enforcement under competing traffic.
- [ ] Offline participation, uplink arrival/loss and no recursive overlay-as-exit egress.

The first implementation now carries explicitly signed RFC1918/ULA endpoint scope through
authenticated connection provenance, selection, endpoint leases, reservations and helper
Prepare/Activate. Each WireGuard lease has its own underlay: Client-facing LAN and Exit-facing
WAN can differ at the same Relay. LAN preparation requires an assigned local address, a unique
connected route and a read-only exact kernel source-to-peer lookup; activation rechecks that
binding. Public-IP validation remains unchanged. Focused checks cover scoped canonical encoding,
local provenance, planner-to-preprobe consumption, mixed-leg signed helper activation and kernel
route parsing. These checks are not live LAN packet evidence, so the datapath items remain open.

LocalOnly Relays are now selectable using an explicit authenticated LAN prefix and an absent
ASN, never a fabricated public origin. Unknown origins conservatively collide with one another;
they cannot be claimed as independent multipath contributions. Exit-facing signed origin
evidence can be explicitly local as well, while the Exit must still declare an independent
Internet uplink. The first [local-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33979923423)
at `0ae30c88` reached neighbor discovery but stopped at `LOCAL_LINK_NATIVE_ROUTE_UNAVAILABLE`:
its Exit incorrectly required its own Client-role control candidate, addressed by the carried
signed authority above. It transferred no proven application traffic.

The local-link scenario now requires two overlapping flows: the offline node consumes through
a WAN-capable Relay and simultaneously relays another node's traffic over two private links
to a different WAN-capable Exit. It checks application hashes, both WireGuard legs, Exit source
addresses, one unchanged offline daemon and the absence of an offline default route. Script
checks pass; this extended giving-and-taking datapath has no passing live result yet.
The [extended run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33982376532) at
`9da11b81` stopped at `LOCAL_LINK_NEIGHBOR_DISCOVERY_UNAVAILABLE`: the offline consumer's
three-peer view was ready, but the second consumer's candidate view stayed empty. It never
reached application traffic; all owned state was cleaned and host-state hashes were unchanged.
The cause was a stale publisher guard requiring an ASN even for `LocalOnly`: the offline
node could consume advertisements but never publish its own Relay capability. The publisher
now accepts truthful LocalOnly Relay service without an ASN or invented public prefix, while
rejecting LocalOnly Exit service. A real signed-advertisement regression and strict agent
Clippy pass; the extended live scenario still needs a successful rerun.
The [publisher-fix rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/33983669024)
at `36e3ae72` admitted the offline Relay and established the offline consumer's native route.
The second consumer still stopped with `PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS`; no complete
two-flow application result is claimed. The local advisory prefix required exactly one control
connection, although simultaneous direct connections are normal. Advisory selection now accepts
multiple currently authenticated connections only when all agree on one consistent local prefix;
each dispatched response still binds its own exact connection witness. Conflicting prefixes,
families, public/circuit addresses and unparsed records remain ineligible.
The [next local-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33984858452)
at `b78a57c5` established both consumers' native routes, then failed at
`LOCAL_LINK_APPLICATION_ECHO_UNAVAILABLE`. The offline application's initial unmarked route
lookup returned `EHOSTUNREACH` before OUTPUT interception. The helper now installs owned
initial lookup rules for unmarked local unprivileged applications, excluding the agent UID,
root/helper observations and marked WireGuard traffic. It does not add a physical default
route or remove the fixture's direct-egress denial. Focused encoding checks and the existing
real marked-ingress/DNS smoke pass; the new initial-route behavior needs a live KVM rerun.
The [initial-route rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/33986598019)
at `63918006` passed the initial send and selected the offline node as the second flow's actual
data Relay. The other consumer received 289 matching echoes through that offline Relay over
about 60 seconds. The offline consumer's destination received 30 requests and emitted replies,
but its application received zero. This proves real contribution, not the complete simultaneous
offline give-and-take scenario; the offline return path remains under diagnosis. Cleanup completed
with unchanged host-state hashes.
The missing-default return path is now reproduced in the disposable ingress smoke with strict
Linux reverse-path filtering: removing the owned reply policy produces one measured RPF drop;
restoring it delivers the exact UDP/DNS source tuple and payload with no further drop. Production
sets source-mark validation only on its own newly created parent veth and marks only replies
arriving from that interface. Existing global/default RPF settings are not weakened. Sixteen
focused ingress tests and strict helper Clippy pass. The earlier KVM artifact lacked RPF counters,
so attributing that exact historical failure remains an inference; new runs retain those counters.
The fixture checks the actual selected Relay before starting applications, retains every draw,
and uses bounded ordinary Disconnect/Connect sampling to exercise the offline data-Relay
assignment. The [RPF-fix run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989039724)
at `a24addac` stopped at `LOCAL_LINK_DATA_CONTRIBUTOR_NOT_SELECTED`: its seven retained reconnects
selected the WAN neighbor as data Relay and the offline node as control Relay. It never started
the application windows, so it does not test the offline reply fix or invalidate the earlier
289-echo contribution witness. Cleanup completed with zero owned objects and unchanged host
hashes. The complete simultaneous offline give-and-take requirement remains open.
Client native preselection and single-path Exit Ready also carry exact observer-bound local
interface hints into their helper Prepare operations. They cannot rely on a public default route
on a LocalOnly node. Multi-path Ready now collects all signed Permits, dispatches Relay Ready
concurrently, and verifies replies with the same sequential replay owner. The Exit waits for
the complete authenticated ordinal/endpoint set before one shared helper Prepare, requiring
exact local traversal hints for each LAN path. Partial sets expire without helper allocation.
Nine focused tests, the mixed-plan real helper encoder check and strict agent Clippy pass;
mixed-path application traffic remains unproven.
The [next v1 run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33986783919)
at `f8660814` stopped during A01 selection. Its Exit collector wrongly required identical
ephemeral Client sessions across paths, although production deliberately creates a distinct
session per path. The collector now compares shared attempt fields while each path retains its
independently signed session/Permit binding. A regression using real Client and Exit signatures
fails before the fix and passes after; all ten Ready tests and strict agent Clippy pass. The
private-address dial guard is unchanged. Live recovery still needs a successful rerun.
The disposable `mixed-link` scenario now reuses the real A06 HTTP/3 transfer with one
LocalOnly LAN Relay and one public Relay to the same Exit. It retains bounded ordinary
selection draws and requires matching 4/8-MiB payload hashes, two genuine native paths,
more than 1 MiB on each WireGuard leg, scoped privacy captures and full cleanup. Its five
focused report/observer checks and shell/workflow contract pass; the
[live run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33987800329) is pending.
It makes no aggregate-bandwidth or real-radio claim.
The [first mixed-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33987800329)
failed before transfer: the public data Relay received the Exit's lexicographically first private
listener, which belonged to another LAN. Permit issuance now selects the exact data Relay's
currently authenticated adjacent listener, or only a public listener for a public peer. A cached
or unrelated private observation cannot choose that address. Ten Permit tests and strict agent
Clippy pass; the private-dial guard and helper endpoint proof remain unchanged. Live recovery is
still pending.
Direct radio setup, simultaneous WAN+LAN aggregation and owner-priority sharing remain
unfinished. No direct-radio or phone-without-SIM support is claimed by Debian KVM evidence.
The first owner-priority **upload** runtime is now implemented behind explicit `sharing`
configuration. One helper-owned netlink queue tree covers aggregate Relay/Exit contribution,
with priority-zero owner traffic ahead of contribution and actual role-specific WireGuard/socket
classification. It starts before participation, survives route-only cleanup and is retired at
daemon shutdown; partial installation remains owned for cleanup. Real disposable-veth
contention/recovery and engine-to-kernel lifecycle checks pass, as do focused wire/config/agent
checks and strict helper/agent Clippy. Standard software `fq_codel` and `mq` roots are also
supported: real single/two-queue TAP tests transfer UDP through the installed aggregate tree
and restore the exact original kernel defaults. Custom roots/options, classifiers, offload and
unsupported queue geometry are rejected before mutation. This does not cover concurrent
administrator changes or crash recovery. The complete-node
[sharing run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33985062548) at `01727102`
installed and removed the scheduler with exact baseline restoration, but stopped at
`SHARING_NATIVE_ROUTE_UNAVAILABLE`: the route's CapacityHold was rejected after the native
probe, before the application/competition windows. The later bounded upload pass is recorded below.
Completed native probes now release their exact Relay and Exit capacity reservations after
confirmed helper destruction, before the real route's next CapacityHold. The signed-chain
regression demonstrates a full-capacity hold failing while the probe is live and succeeding
immediately afterward, without waiting for TTL; stale probe authorization cannot reacquire
that capacity. The configured sharing/advertisement limits are unchanged.
The [next sharing run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33986599058)
at `63918006` reached all three real traffic windows and restored the original scheduler.
Under owner load it measured 11.999 Mbps owner upload and zero contributed upload, within the
12-Mbps physical cap. Idle/recovery contribution was only 3.446/3.504 Mbps, below the required
4 Mbps, so the scenario still failed. General UDP's stop-and-wait bottleneck is now removed:
bounded reverse draining is independent of subsequent sends; explicit transient native TX
backpressure drops one continuation without destroying the route. Startup authorization and
the separate DNS association retain their original bounded semantics. Four focused pipeline
tests, the exact ingress tuple test and strict agent Clippy pass. The
[new live sharing run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33988084401)
proved two actual requests before the first echo and increased idle contribution to 9.764 Mbps.
Owner traffic retained 12.002 Mbps while contribution yielded to zero. Recovery was only
3.685 Mbps, below the unchanged 60%-of-idle/4-Mbps floor, and the Exit observer lost 28 frames:
the run still failed. The contribution band now uses bounded kernel FQ-CoDel flow queuing under
the same priority and rate caps, instead of one tail-drop FIFO shared by Exit UDP and encrypted
feedback. Six focused sharing tests, including real veth and single/multiqueue TAP restoration,
and strict helper Clippy pass. The disposable packet
observer also requests a verified bounded 4-MiB socket buffer without changing a global sysctl;
zero capture drops remain mandatory. Throughput checks are not weakened.
The [corrected sharing run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989126592)
at `21aa8f21` **passed** the complete upload scenario: contributed traffic measured 5.430 Mbps
when idle, yielded to zero while the owner received 11.996 Mbps of the 12-Mbps uplink, and
recovered to 7.377 Mbps. The same protected UDP context delivered 1643/2/2226 exact echoes across
those windows through one selected Relay and both WireGuard legs. Two destination requests
preceded the first reply, proving actual pipelining. All four packet observers reported zero
drops, direct Client--Exit packets and plaintext leaks; exact scheduler/guest-network baselines
were restored with zero owned objects. These are queue/physical upload measurements, not
application goodput or a promise of these rates on other links.
The fixture's Exit-side Disconnect was on an idle local Client route, so its result does not
prove retirement of an active same-node route while sharing; exact scheduler teardown is proven.
Download control, automatic available-bandwidth estimation and radio airtime remain unfinished.
These narrower results do not check the full sharing item above.

The first explicit Debian `wifi_mesh` runtime is implemented and its kernel backend has passed
the disposable simulated-radio proof below. Full-agent mesh routing and physical radios remain open.
The helper creates one separately owned open-L2 802.11s interface using nl80211, with a bounded
private connected subnet and no default route. Existing active radio interfaces are not retuned;
unsupported/regulatory/coexistence conditions are rejected. The agent creates the interface
before its mesh listeners/bootstrap dials, inspects the exact owner periodically and retires it
after route shutdown. Kernel link-layer forwarding and automatic address/default-route acquisition
are disabled on the new interface. Nine focused kernel/engine tests and four wire/config/agent
tests pass; strict helper and agent Clippy pass. This is not SAE, LAN host-service isolation, physical-radio
coexistence, mobile support, airtime management or a speed-increase claim.
The disposable `wifi-mesh` scenario now builds the real helper backend harness and creates two
`mac80211_hwsim` radios. The pinned cloud guest kernel omits wireless support, so this scenario
alone installs the exact hash-verified Debian generic kernel `6.12.107+deb13-amd64` and reboots
its disposable overlay once. The harness requires real mesh peering, bidirectional 128-KiB hashes,
station byte/packet counters, explicit removal and socket-loss cleanup. Parser/preview checks,
ShellCheck and helper Clippy pass. The
[live hwsim run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989125353)
at `21aa8f21` **passed**: two different wiphys reached kernel ESTABLISHED peering, each direction
transferred exactly 131072 bytes with matching crossed hashes, and real station byte/packet
counters increased. Both normal removals were idempotent, closing the crashed owner's socket
removed its exact interface, and namespace/guest-network baselines were restored with zero owned
objects remaining. This is real kernel 802.11s behavior on simulated radios, not physical-radio,
phone, capacity-gain or full-agent-overlay evidence.
See [local-link scope](LOCAL_LINK_NETWORK.md).

## Fixed alpha v1 scorecard

This scorecard measures progress toward a **working alpha**, separately from
the detailed implementation checklist below. Within alpha v1, the rows, names,
IDs, criteria, weights, 100-point threshold, and A01--A15 definitions are frozen
as of 2026-08-26; only State and supporting evidence may change. The normative
baseline is repository commit `14d7f2b02a70dd626b5f6b7ba06348ac3dd48b9c`
with `AGENTS.md` SHA-256
`4c766b1f81c428f5862557c1c4d3c1cc0fbdd308f7944c2dd92e9d6a64dbee75`.
A fully tested,
explicitly named foundation, core, or boundary may earn only its own points
before it has a production caller. Partial work, mocks, and dormant code earn
no downstream production or dataplane points. An earned milestone can lose
points only when a regression invalidates its evidence, not because the work is
later estimated with a different ruler. Any future scope change must publish a
visibly versioned replacement table instead of silently changing this one.
The short milestone labels incorporate all corresponding normative-baseline
privacy, policy, host-safety, cryptographic, path-count, no-fallback, and
evidence requirements; their omission from a short label never relaxes an
invariant.

| ID | Milestone | Points | State | Evidence |
| --- | --- | ---: | --- | --- |
| AV1-01 | GPL source/licensing, pinned native provenance and separate RustSec audit gates | 3 | Earned | [Repository baseline](#repository-and-engineering-baseline), [testing](#testing-and-fuzzing) |
| AV1-02 | Validated configuration/default roles and encrypted permanent node identity | 3 | Earned | [Configuration](#configuration-and-roles), [identity](#identity-and-signed-protocol) |
| AV1-03 | Threshold-signed whitelist manifest and fail-closed matching core | 3 | Earned | [Policy](#policy-and-whitelist-enforcement) |
| AV1-04 | Native API-v6 process, framing, descriptor, replay and client-assignment boundary | 2 | Earned | [Native boundary](#genuine-multipath-quic--masque), [testing](#testing-and-fuzzing) |
| AV1-05 | Canonical signed control envelopes, replay/TTL and compromise recovery | 3 | Open | — |
| AV1-06 | Live libp2p discovery, capability indexes and replaceable bootstrap | 5 | Open | — |
| AV1-07 | Exit-first path selection, measurements, capacity and diversity | 5 | Open | — |
| AV1-08 | Production FreshEvidence, reservations and exact-set join | 5 | Open | — |
| AV1-09 | Production helper identity, authenticated IPC and operation allowlist | 6 | Open | — |
| AV1-10 | Durable helper ownership journal, restart reaper and crash settlement | 5 | Open | — |
| AV1-11 | Ephemeral-key two-leg WireGuard paths, relay fence/no relay egress or host access, exit-only egress | 9 | Open | — |
| AV1-12 | Route orchestration, descriptor handoff, expiry and complete cleanup | 5 | Open | — |
| AV1-13 | Transparent ingress, kill switch, DNS routing and loop prevention | 6 | Open | — |
| AV1-14 | Live exit resolution/SNI/QUIC/general-UDP whitelist enforcement | 6 | Open | — |
| AV1-15 | Single-path QUIC MASQUE UDP through exactly one relay | 6 | Open | — |
| AV1-16 | Transparent TLS 1.3 framing over real multi-subflow kernel MPTCP, without ordinary-TCP fallback | 9 | Open | — |
| AV1-17 | Browser QUIC over genuine MPQUIC/MASQUE on at least two data-carrying distinct-relay paths, fail closed/failover | 10 | Open | — |
| AV1-18 | Debian 13 doctor, hardened services, privacy-safe logs/retention, reproducible package and operations | 3 | Open | — |
| AV1-19 | Disposable full-topology runner and machine-readable evidence | 3 | Open | — |
| AV1-20 | One unchanged clean build passes all required quality gates and A01--A15, including privacy and host safety | 3 | Open | — |

Historical pre-vertical checkpoint: **11/100 (11%)**, not a current estimate.
The original v1 completion criterion remains **100/100** and the clean-build A01--A15
proof; the newly required reciprocal datapath must also be demonstrated.

## Repository and engineering baseline

- [x] Workspace is a Git repository.
- [x] Durable repository rules are recorded in `AGENTS.md`.
- [x] The Rust workspace and required crate layout compile on stable Rust after the
  hard-incompatible privacy-v4 discovery and route-setup migration.
- [x] GPL-3.0-only licensing, including the standalone fuzz package and new
  local mqvpn patch files, and compatible third-party notices are complete.
- [ ] Workspace formatting, strict Clippy, tests, and the dependency gates must pass together for
  the accepted exact revision; no current exact-revision evidence is recorded here yet.
- [ ] Pinned Cargo-deny 0.18.6 performs the required all-in-one offline root and fuzz checks with
  CVSS 4.0 support; pinned Cargo-audit 0.22.1 independently checks both graphs for unremediated
  vulnerabilities. Mark this complete only from the accepted exact-revision Quality run.
- [x] `justfile` exposes every required build, test, fuzz, benchmark, doctor, demo, package,
  and cleanup entrypoint. Real execution drivers exist in `tests/integration/run.sh`,
  `tests/integration/run-alpha-topology-vm.sh` and `packaging/build-deb.sh`; preview remains
  non-mutating, and the integration preview reports `BLOCKED` because execution was not requested.
- [ ] No essential production datapath contains a mock, stub, `TODO`, or `unimplemented!()`.
- [ ] Clean Debian 13 amd64 build is reproduced.

## Configuration and roles

- [x] The shipped `config/examples/default.yaml` is parsed and validated in a regression test and
  is exactly equal to the fully validated `Config::default()` snapshot.
- [x] Client, relay and exit all default disabled in `RolesConfig` and the shipped YAML.
  Production consumption requires relay contribution, plus exit contribution when the operator
  declares an independent Internet uplink; local-only nodes cannot enable exit service.
- [x] Unsafe combinations, invalid bounds, and unknown safety-sensitive fields fail closed.
- [ ] `routing.direct_exit_debug` defaults off and production rejects it; explicit development
  configuration accepts it, but no debug datapath or prominent runtime warning is implemented.
- [ ] A private atomic role store initializes startup roles. Privacy-v4 protocol directions are
  immutable after process start; runtime changes return restart-required without mutation or
  persistence. No controlled apply/restart workflow or live service-readiness proof exists.
- [ ] Route-context TTL, flow pinning, maximum contexts, and LRU cleanup exist as tested cache
  primitives. Production `ClientRouteControl` in `volparossa-agent/src/route_setup.rs` now owns
  established transport contexts, binds policy-authorized flows and retires signed/idle-expired
  owners through helper cleanup. This does not complete the generic multi-origin context-cache
  and LRU integration; that broader requirement remains unchecked.

## Processes and privilege separation

- [ ] `volparossa` CLI implements every command in the master specification.
- [ ] Unprivileged `volparossa-agent` owns control-plane, selection, sessions, and local metrics.
- [ ] Minimal `volparossa-helper` owns only allowlisted privileged network operations; v3
  has a bounded typed external state machine plus a child bootstrap that applies and
  independently verifies NEWNET, pre-barrier NNP plus a fixed descendant-and-namespace-transition
  denying seccomp filter, a parent-pinned pre-drop namespace, exact descriptors and one task, an
  exact dedicated non-root UID/GID with empty supplementary groups, exact capability reduction,
  restored parent-death signal,
  credential-bound staged proof-to-Accepted-to-Ready, a second parent-side descriptor audit after
  proof, and leader pin retention. The parent attests
  filter mode plus exactly one filter beyond its pre-spawn thread baseline; exact BPF content is
  structurally bound by the current executable's fixed UAPI rather than claimed from `/proc`.
  `clone`, `clone3`, `fork`, `vfork`, `setns` and `unshare` monotonically return `EPERM` before the
  namespace-pin barrier, including post-Ready and across exec. After the parent has independently
  observed the final sandbox and sent Accepted, the child disables and reads back `PR_SET_DUMPABLE`
  before Ready or any operational request; the fixed service and transient live-proof driver also
  set `LimitCORE=0`. The production server now uses it only for a Client/Exit-singleton-or-Relay-pair
  functional-alpha Prepare/Activate/Probe-Commit/Destroy backend. Activate requires and verifies the
  exact nested relay/exit signed grant and binds it to helper-owned context/path/role/expiry. Relay
  additionally verifies the outer client-session-signed request, its embedded signed
  ClientSessionCapability and ExitReservation, the relay-signed SHA-256 commitment to the exact
  request bytes and complete capability/exit/authorization/session/rate/endpoint scope. Those five
  signed records form one rollback-capable replay transaction. Client
  binds its prepared key and installs only the signed relay-client peer; Exit binds its complete
  prepared key/public-underlay/listen-port tuple to the dual-signed exit endpoint and installs only
  the relay-signed relay-exit peer. Both roles install a derived `/128` route and retain their kernel
  counters as the activation baseline. The ordered `RelayClient` + `RelayExit` pair binds both
  prepared local tuples to the relay-signed endpoints, installs only the client-request and nested
  exit-signed peers on their respective leases, and rolls back the complete pair on partial failure.
  Commit succeeds only after an exact correlated worker probe proves a handshake no older than
  activation and strict growth of both RX and TX for every lease; neither Relay leg commits alone.
  For a Relay pair, the child creates a generation-pinned empty policy-drop nftables baseline
  before either link exists. Activate enables IPv6 forwarding only inside that worker namespace
  and atomically installs two exact `/128` direction rules bound to the authenticated ifindices,
  source/destination pair, byte rates, a jiffies-based singleton timeout and an independent
  realtime cutoff, followed by a terminal drop. Commit also requires strict growth of both
  forwarding counters. Complete-pair Destroy restores policy-drop before removing both links and
  proves exact fence absence before ownership is released. Transport, ingress and usable product
  datapath operations deliberately return `Unavailable`. The package declares a locked,
  group-isolated `volparossa-worker`, pins its numeric
  identity at startup, and first binds unique local passwd/group names and numeric IDs to exact
  name- and number-based NSS results. Only the canonical `files` or `files systemd` order is
  accepted for passwd/group/shadow and optional initgroups; service group sets must exactly match
  the local package contract. It excludes both service identities from the live `shadow` group and validates
  unique agent and worker shadow entries from one zeroizing snapshot: both passwords begin with
  `!`, the worker account expiry is exactly `1`, and root-owned metadata is not writable by either
  service identity, with group read limited to the resolved
  `shadow` group. The bounded zeroizing read cannot reallocate hashes. This is still not complete isolation or
  context cleanup: the Client and Exit singleton cycles and the Relay endpoint-pair cycle have
  separate retained exact-main Debian 13
  live-root PASS evidence for the identity transition, parent-signal and runtime-path denials,
  pre-filter process-tree state and equal enumerated host-state fences, but retirement still owns
  only the exact leader. A preview-first root driver now
  stages the real
  component in a transient `PrivateNetwork` systemd unit with synthetic read-only account overlays,
  a private `/run`, the exact seven-capability parent set, exact singleton staged-agent
  supplementary-group attestation (so inherited host-root groups fail closed), confirmed leader
  reap and privacy-safe before/after host-state digests. That driver now requires exact systemd
  v257, retains the shipped `NotifyAccess=main`, 128-entry descriptor-store maximum and
  preserve-on-stop setting, binds only the system bus socket read-only into its private `/run`, pins
  `DBUS_SYSTEM_BUS_ADDRESS` to that verified socket path, and
  accepts the live-proof-only publication path only when the two ordered proof records and external
  post-exit `NFileDescriptorStore=2` agree. Its exact-unit retirement cleans only `fdstore`; the
  normal route binds every mutation to the returned JSON ID, while tentative recovery may adopt a
  current nonzero systemd v257 `InvocationID` only after exact per-stage marker proof. Failed units
  are reset inactive before cleaning, and anything other than a bounded zero-count or
  not-found result is failure. An interrupt window is covered by an atomically installed per-stage
  SHA-256 `Description` marker: tentative ownership can become mutable only after bounded read-only
  proof of the exact marker and a nonzero current ID. Remaining ambiguity causes zero unit mutation
  and requires discarding the disposable VM. After that first unit is collected, the same driver
  now requires its cgroup to be absent before reusing the random unit name with a different marker
  and `InvocationID` for the true argumentless production server. A fixed, closed-mode probe first
  proves two same-process read-only runtime binds, bounded frame and canonical-wire rejection, and
  independent
  wrong-UID, wrong-primary-GID and root-peer rejection after each peer has passed Unix DAC. Every
  probe pins the server's `SO_PEERCRED` PID/GID to the exact unit `MainPID`/agent GID and brackets one
  socket inode. The retained-evidence producer now stages the non-empty helper and IPC probe under
  separate 128 MiB ceilings with workspace ownership, single-link, metadata, and digest fencing;
  only after those copies does it set and verify its own 1 MiB ceiling before any hook, account,
  capture, or report write. PID 1 independently enforces the unit's three-minute maximum lifetime
  and 1 MiB file-size limit while unit stdout/stderr go to `null`. Normal `SIGTERM` retirement must
  leave the journal byte-for-byte and metadata-identical, release the same captured lock inode
  proven exclusively held while the helper ran, remove the socket, empty the descriptor store and
  remove the exact old process and
  cgroup. Both phases use a private runtime bind and require host `/run/volparossa` to remain
  absent. The resolver host-state fence now binds the exact root-owned Debian symlink to only the
  two fixed `systemd-resolved` targets and the current active service's exact non-root UID/GID,
  process credentials, invocation, mode and runtime-directory identity; generic non-root owners
  under `/run` remain rejected. Repeated private authority/object/target captures reject restart,
  replacement, mixed ownership, writable paths and content drift without publishing DNS state.
  The seven network JSON state normalizers now require exact document and entry shapes, bind
  separately captured IPv4/IPv6 route and rule records to their canonical source family, reject
  malformed flags and suppress data-dependent parser stderr; only fixed failure labels can enter a
  retained diagnostic artifact. The firewall fence now treats canonical nft JSON as the
  `nf_tables` authority and consults only `/proc/self/net/ip_tables_names` and
  `/proc/self/net/ip6_tables_names` for separate legacy `x_tables` custody. It distinguishes absent,
  empty and present inventories; a present family requires two identical normalized executions of
  the fixed `/usr/sbin/iptables-legacy-save -M /bin/false` or
  `/usr/sbin/ip6tables-legacy-save -M /bin/false` producer, with identical inventories and
  bracketing nft observations. Raw table names and rules remain in the root-only stage; retained
  records contain privacy-safe digests and diagnostics only fixed labels. Equality proves stable
  observations at the two fences, not continuous stability between them.
  The same closed probe then creates one fixed dummy underlay only inside the production unit's
  `PrivateNetwork` and runs two sequential singleton cycles. Client Prepare/Activate pauses at its
  root-owned READY barrier while the hook checks the exact child, namespace, relay-client peer and
  derived `/128` route; a temporary relay-side WireGuard peer carries bounded ICMPv6 and proves a
  recent handshake plus strict RX/TX growth before exact fixture cleanup, Commit with byte-identical
  retry and exact/idempotent Destroy. The second cycle then starts an Exit context in a different
  child PID and network namespace. It binds the helper-prepared local tuple to the dual-signed exit
  endpoint, installs the relay-signed relay-exit peer, and pauses at a separate READY barrier. A
  distinct `vpre0` fixture with a second deterministic key carries bounded ICMPv6 over a real,
  separate relay-to-exit WireGuard leg, proves recent handshake and strict bidirectional growth, and
  is removed by exact alias/ifindex/WireGuard-kind lineage before Exit Commit with byte-identical
  retry and Destroy. The older retained run's third, separate worker/namespace cycle exercised the
  exact ordered Relay endpoint pair, with two simultaneous external endpoint fixtures, both
  handshakes and strict RX/TX growth required before pair Commit, followed by complete-pair Destroy.
  Exact-main run 33301595311 at `0095b113e450a0ab29da853fafa53b2b130f05fc`
  retained that Relay-pair proof as artifact 9729172274. That retained fixture installed no
  cross-leg forwarding.
  Final checks require zero helper children and no helper FD retaining a worker namespace or any
  foreign worker network namespace. Each cycle's retired process pin must be terminal and its pinned
  namespace WireGuard-empty before that observer closes; the descriptor store must be empty and the
  fixed exact-one-loopback/no-default-route cleanup predicate must hold after fixture removal.
  A successful execute-mode run now emits one bounded canonical helper-boundary evidence-v1
  JSON document on stdout only after separate observed clean-source and executed-artifact
  bookends, both distinct invocations, retirement, equal digests for the exact enumerated host
  records at two fences, strict semantic validation and removal of the root-only stage; human
  output is confined to stderr. It does not infer that a pre-existing binary was built from the
  observed commit. Its validator rejects reordered or missing
  checks and malformed or internally inconsistent false-PASS combinations; it is not a
  cryptographic attestation of who ran the producer. A manual two-mode workflow and a
  preview-first KVM/QEMU driver now pin a manually reviewed Debian image and its checksum provenance,
  transfer only a clean tracked source clone, fetch locked dependencies in a provisioning boot,
  then deny proof-boot egress and build offline. Ephemeral SSH host identity, pidfd-bound QEMU
  cleanup, active log bounds, exact environment/report crosslinks and post-use image hashing fail
  closed; their unprivileged contracts pass. Selecting `main` requires retained, host-revalidated
  evidence; selecting one canonical non-main branch runs the same exact branch/SHA proof as
  `non-retained-pr-smoke`. On PASS it validates the proof internally, discards every proof file and
  requires an empty output directory; the workflow uploads neither branch PASS artifacts nor branch
  failure diagnostics. This is manual branch selection rather than an automatic pull-request trigger.
  Client exact-main run 33294974441 at `77b60aed3c39ba0c80d3e2dac2b9817fd6d7be2f` retained artifact
  9727163813. Exit exact-main run 33296892632 at
  `1ca51fe0d2a2be855adb182e85c229d1d12bc017` succeeded and retained artifact 9727739271. Relay-pair
  exact-main run 33301595311 at `0095b113e450a0ab29da853fafa53b2b130f05fc` succeeded and retained
  artifact 9729172274. Relay-forwarding exact-main run 33309109220 at
  `1f3cee798787ed4673a3ba28d88931947800ca22` succeeded and retained artifact 9731470248. These
  self-contained fixture identities do not validate trusted
  selection/policy authority or provide an independent discovery/connection trust anchor, a
  production simultaneous two-leg route, transport descriptor, ingress, usable VPN
  datapath, crash recovery, installed package or shipped-unit restart behavior. A non-retained
  branch PASS closes no A01--A15 checkbox or scorecard row. The score remains
  **11/100 (11%)**.
  The private capture and production-lock metadata predicates now use the numeric regular-file
  type plus exact owner, mode and single-link fields, so intentionally empty successful stderr,
  validator and lock files are not misclassified by GNU `stat` as a different type. Content
  emptiness, non-emptiness and shape remain separate fail-closed checks wherever content has a
  semantic contract; lock contents carry no such claim. The post-merge
  [helper-boundary run 33136739229](https://github.com/VOLPAROSSA/volparossa/actions/runs/33136739229)
  at `d54057111dde8ea47970e8708aff7ea8e2af5eb6` retained only diagnostic artifact
  `9672404397` (API archive SHA-256
  `e58e138016160e96174bcf174cbaa397083d1d3b0043c37ee7bf20c34025f531`) and exposed that
  proof-control defect before report publication. After that defect was fixed, exact-main
  [run 33141845396](https://github.com/VOLPAROSSA/volparossa/actions/runs/33141845396) at
  `193d460c0f0ab20d968bd4589f03ea7908a2ce60` retained diagnostic artifact `9674312274`
  (API archive SHA-256
  `a7b9711f150f523acd32185367b823836053cee8a13c83a3f698f84bf201c697`) with the first fixed
  rejection label `worker-launch-status`. Exact systemd v257 source and a non-mutating local
  reproduction bind this to `systemd-run` preflighting the absolute private `/run` helper path in
  the host namespace before PID 1 could create the unit. Both transient calls now provide and
  read back one fixed `ExecSearchPath`, which suppresses that client-side preflight while retaining
  absolute bound command paths and the fixed child `PATH`. Exact-main
  [run 33144430325](https://github.com/VOLPAROSSA/volparossa/actions/runs/33144430325) at
  `9cb0e984c9147888c5ac437c8089702c3b8f4ac3` retained diagnostic artifact `9675288585`
  (API archive SHA-256
  `53093ed0ef963b25e3d576d662adf1a4c5a549ea681fae53775157efbcab16d3`) and still stopped at
  `worker-launch-status`. The exact systemd v257 property tables expose the next client-side
  rejection: `ProtectControlGroups` accepts only a boolean while the required `strict` enum must be
  sent as `ProtectControlGroupsEx`. Both transient calls now use that string-valued property and
  the static contract forbids the invalid legacy spelling. The same source audit also shows that a
  standalone private `/run` does not automatically restore PID 1's notify socket, although both the
  live FD-store publication and production startup inventory require it. The gate therefore
  validates the canonical root-owned `/run/systemd/notify` socket and binds it read-only into both
  transient mount namespaces. Exact-main
  [run 33147652050](https://github.com/VOLPAROSSA/volparossa/actions/runs/33147652050) at
  `d4687fe9dd07724ff438ff2ccfa653668b2f7d24` then retained diagnostic artifact `9676480232`
  (API archive SHA-256
  `4f3a3da89f630b052953951a026e51e5a9825b46743f16130d728ea7bbf659a4`) with the first fixed
  rejection label `worker-terminal-state`. This proves that PID 1 reached the staged helper main
  process, but not which internal live-proof boundary rejected. The artifact also exposed two
  Debian `mawk` parse failures in the later capability normalizer because its loop variable used
  awk's built-in `index` name. The normalizer now uses a non-reserved variable and its exact
  production body is exercised dynamically by the shell contract test. A failed helper main now
  emits exactly one payload-free, versioned stage record for parent contract, runtime preparation,
  worker spawn, FD-store publication, or retirement cleanup. The driver accepts that record only
  from a safe byte-exact private capture bound to the current manager marker and invocation and the
  exact `failed:failed:exit-code:1:1` terminal tuple; malformed, additional, truncated, unknown,
  signalled, launch or manager failures retain a generic fixed label. Exact-main
  [run 33151307859](https://github.com/VOLPAROSSA/volparossa/actions/runs/33151307859) at
  `175defc28c8a1297a8ad23b919abe5c427630ed9` retained diagnostic artifact `9677903781`
  (API archive SHA-256
  `1a49ec8c21da443dfb3cac2804fcc859006fecb9122a36384256d2c824e8fc68`) with the same
  `worker-terminal-state` label and no `mawk` error, proving the normalizer correction while still
  withholding PASS. Exact systemd v257 source then exposed the deterministic launch-contract
  mismatch: `--ignore-failure` converted the helper's diagnostic exit 1 into unit success, while
  the classifier correctly required a failed terminal tuple; `--collect` could additionally
  discard other failed terminal state before inspection. The diagnostic unit now uses blocking
  `Type=exec` startup, so PID 1 owns the exec boundary and a helper exit 1 remains a real unit
  failure. Both transient units forbid those two shortcuts, pin and read back `Type=exec` and
  `CollectMode=inactive`, and attest exact diagnostic/production `RemainAfterExit` values. The
  diagnostic unit separately pins and reads back a 45-second runtime maximum. Attempt 3 of exact-main
  [run 33154240154](https://github.com/VOLPAROSSA/volparossa/actions/runs/33154240154/attempts/3)
  at `9277f34b6d4bdf6c673808f916e8530e0772529c` ran the real disposable VM in
  [job 99120406794](https://github.com/VOLPAROSSA/volparossa/actions/runs/33154240154/job/99120406794)
  and retained diagnostic artifact
  [9717037736](https://github.com/VOLPAROSSA/volparossa/actions/runs/33154240154/artifacts/9717037736)
  (API archive SHA-256
  `ea62e06f75049d986465f49dba8b3cfb17aaa9815f6b6d6fd276bb6d2bb533fa`) with first fixed label
  `worker-launch-status`. Exact systemd v257 `start_transient_service` control flow explains this
  result: the blocking client returns from a failed `bus_wait_for_jobs_one` before its subsequent
  `acquire_invocation_id` and JSON-print path, so the short failed helper had an exact PID 1 unit but
  no client JSON binding. The gate now recovers diagnostic binding only for nonzero status, safe
  captures, exactly empty client stdout, absent JSON binding and successful tentative adoption of
  the exact random name, SHA-256 marker and nonzero current manager ID. It rechecks marker and ID
  after adoption and again before mapping the byte-exact stage. Nonempty or malformed stdout,
  `not-found`, marker/ID drift and failed observations remain generic. This exception cannot pass
  the proof: success still requires status zero, exact JSON, empty client stderr and the exact
  successful terminal tuple. A non-retained helper-boundary branch smoke
  [run 33270993243](https://github.com/VOLPAROSSA/volparossa/actions/runs/33270993243) at
  `b4eb5eed8ee601e7f63ff71f45d7a9b2244feb61` then reached the exact bounded diagnostic
  `terminal-failed-exit-status-216,stage-empty`, still classified as `worker-launch-status`.
  systemd's status 216 is `EXIT_GROUP`: v257 resolves static `Group=` credentials before creating
  the unit mount namespace, while the gate deliberately selected a staged GID absent from the host
  account database. Its private `/etc/group` bind was therefore necessarily too late. Both
  transient services now give PID 1 only host-resolvable root/root credentials and use the exact
  validated root-owned `/usr/bin/setpriv` trampoline, after namespace construction, to install the
  raw staged primary and singleton supplementary GID before executing the helper in the same
  MainPID. The diagnostic helper parent contract continues to attest the final identity,
  capabilities, no-new-privileges state and seccomp state. The production hook independently
  requires and repeatedly revalidates all four UID/GID fields, its singleton group, NNP, seccomp
  mode and bounded filter count, and all five capability masks against the exact seven-capability
  set. The next non-retained branch smoke
  [run 33272380911](https://github.com/VOLPAROSSA/volparossa/actions/runs/33272380911) at
  `4dad3621fe9ec43ac23de432f57f6b0b7a3582ca` ran the disposable VM in
  [job 99153099364](https://github.com/VOLPAROSSA/volparossa/actions/runs/33272380911/job/99153099364)
  and reached the helper-emitted fixed category `worker-helper-worker-spawn`. This proves that PID 1
  executed the staged helper after the `setpriv` transition and that the helper passed its exact
  parent contract plus production-runtime preparation before its internal worker failed. Exact
  systemd v257.13 source identifies the deterministic incompatibility: `RestrictSUIDSGID=yes`
  installs a separate seccomp filter that returns `ENOSYS` for every `openat2(2)` call because its
  mode is inside the indirect `open_how` argument. The worker parent intentionally uses rustix's
  non-fallback `openat2` immediately: ordinary process records and cgroup paths use
  `RESOLVE_BENEATH`, `NO_MAGICLINKS` and `NO_SYMLINKS`, while only the fixed `exe` and `ns/cgroup`
  procfs magic links are deliberately followed relative to the already pinned exact process
  directory. The rejection therefore fails closed instead of silently weakening either resolution
  contract. The shipped helper and both transient helper
  profiles now explicitly set and read back `RestrictSUIDSGID=no`; the doctor makes this exception
  helper-specific, while the agent and native MPQUIC services retain `yes`. Compensating boundaries
  remain the typed path-free helper protocol, `NoNewPrivileges=yes`, strict filesystem protection,
  fixed host-visible writable runtime paths, private transient temporary filesystems (including a
  `nosuid,noexec` `/run`), `UMask=0077`, and the absence of `CAP_CHOWN`, `CAP_FSETID` and
  `CAP_SETFCAP` from the helper capability set. The resulting non-retained branch smoke
  [run 33273482691](https://github.com/VOLPAROSSA/volparossa/actions/runs/33273482691) at
  `7f23bc855b7f9922f9b055cb95098394d913313c` ran the disposable VM in
  [job 99156047492](https://github.com/VOLPAROSSA/volparossa/actions/runs/33273482691/job/99156047492)
  and advanced to the fixed first-failure category `worker-confinement`. The earlier ordered
  predicates therefore prove that the diagnostic helper completed its internal live-worker proof,
  published both exact records and left two descriptors in PID 1's store. The retained category
  intentionally did not reveal which of the capability bounding set, ambient capability set,
  private-network flag or exact control-group readback failed, so no production correction is
  inferred from it. The gate now retains only the first matching fixed subcategory (`bounding`,
  `ambient`, `private-network` or `control-group`) and the non-retained driver exposes that label
  only when the generic first failure is exactly `worker-confinement`; missing, duplicated,
  malformed and non-allowlisted diagnostic records expose nothing. None of the failed runs is PASS
  evidence. The follow-up non-retained branch smoke
  [run 33274272679](https://github.com/VOLPAROSSA/volparossa/actions/runs/33274272679) at
  `80e0dd077ceab4c8c8a33590a83299e179dde10f` ran the disposable VM in
  [job 99158142816](https://github.com/VOLPAROSSA/volparossa/actions/runs/33274272679/job/99158142816)
  and retained the exact `control-group` subcategory. The worker's preceding internal live proof had
  already pinned the helper parent and worker to the same cgroup path and inode while both existed.
  The external manager observation happened only after the deliberately retained
  `Type=exec` unit reached `active (exited)`: systemd had then released the empty service cgroup and
  returned an empty `ControlGroup`, even though the unit metadata remained loaded. This was a
  terminal evidence-contract defect, not evidence of incorrect live placement. The diagnostic
  transient unit now explicitly selects `system.slice`; after terminal state the gate requires the
  manager's `ControlGroup` to be exactly empty and `Slice` to be exactly `system.slice`, then derives
  the fixed
  `/system.slice/<exact-random-unit-name>` only for bounded post-retirement cgroup-absence checks.
  The production transient unit also selects and reads back exact `Slice=system.slice`, remains
  running during observation, and still requires exact live
  `ControlGroup=/system.slice/<exact-random-unit-name>` readback. The next non-retained branch smoke
  [run 33275030601](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275030601) at
  `20f8a121f7aa020450587251dad9de66ec7738fc` ran the disposable VM in
  [job 99160142810](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275030601/job/99160142810)
  but exited with shell status 2 before the fixed final failure line, leaving only `unclassified`.
  Static review found two production-observation paths capable of masking their fixed predicate:
  missing or unsafe `unit.identity` could leave its later retirement executable operand unset under
  `set -u`, and redirection failure on special builtin `exec` could terminate the shell rather than
  enter its recorded lock-release failure branch. The identity fields now start empty and the probe
  uses ordinary-failure `command exec`. The EXIT cleanup also emits one fixed value-free monotonic
  phase only when a nonzero exit occurs before normal final reporting, without changing original or
  cleanup status; branch smoke may expose that phase only with `unclassified` and rejects missing,
  duplicate, malformed, mixed or privacy-unsafe records. This run is not PASS evidence. At that
  revision the score remained **11/100** and a new exact-main retained run was still required. The next
  non-retained branch smoke
  [run 33275945986](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275945986) at
  `38ee44a81991f660168a76342584416d04a6ef5d` ran the disposable VM in
  [job 99162565524](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275945986/job/99162565524)
  and reached the fixed first failure `production-launch-status`. Production service stdout and
  stderr intentionally remained null, so this result does not identify which fixed `ExecStartPost`
  assertion failed. The start hook now maintains one fixed monotonic allowlist spanning combined
  preflight/runtime validation, helper identity, active-lock proof, each protocol-probe group,
  functional underlay, probe-ready, worker observation, probe finish, cleanup and final publication.
  Any failed start atomically writes at most one root-owned, mode-0600, single-link
  `start.failure`; every hook descriptor open and close uses ordinary-failure `command exec`, so a
  redirection failure reaches that record instead of terminating the shell as a special builtin.
  The live gate parses an exact canonical record only when its first failure remains
  `production-launch-status`, and the branch runner exposes only the fixed stage paired with that
  exact category. Missing, duplicate, malformed, mixed and privacy-unsafe records expose no stage;
  raw hook messages and service streams remain unavailable. Run 33275945986 is not PASS evidence;
  at that revision the score remained **11/100** and AV1-09 remained Open.
  Exact branch [run 33278664815](https://github.com/VOLPAROSSA/volparossa/actions/runs/33278664815)
  at `b050fe576ebd2e77cc4d3c871dad22f9d91e267b` then ran the disposable VM in
  [job 99169908991](https://github.com/VOLPAROSSA/volparossa/actions/runs/33278664815/job/99169908991)
  and retained `production-launch-status` with diagnostic `identity-command`. That failed run is
  not PASS evidence. Static reproduction identified an evidence defect: the separately confined
  root hook cannot honestly read the non-dumpable staged-agent process's `/proc/<pid>/cmdline` or
  `exe` magic link without ptrace-equivalent authority. The proof does not add `CAP_SYS_PTRACE` or
  a private-manager bind. Instead, `identity-launch` reads both systemd v257 `ExecStart` and
  `ExecStartEx` over the policy-mediated system bus and requires their exact ten-field signatures,
  empty/false flags, running timestamps, `MainPID`, and the exact
  `/usr/bin/setpriv --regid=<agent-gid> --groups=<agent-gid> --
  /run/volparossa-helper-production` tuple. `identity-birth` binds that command to the root-owned,
  mode-0500, single-link helper image: it records metadata plus one SHA-256 that must equal the
  driver's fenced staged digest, while later checks re-read metadata instead of repeatedly hashing
  the roughly 78 MiB image. The manager `InvocationID` and `MainPID`, canonical
  `/proc/<pid>/stat` starttime, exact process-status record, second starttime, image metadata,
  `MainPID`, and `InvocationID` form one forward/reverse replacement and PID-reuse bracket. Every
  authenticated probe still requires server `SO_PEERCRED` to equal that exact `MainPID` and is
  bracketed by the complete identity artifact. Retirement distinguishes the old process from PID
  reuse by starttime and fails closed when an extant proc record becomes unreadable. The worker
  observation likewise makes no cross-credential executable claim. Source-pinned
  `ExecStartPost`/`ExecStopPost` commands now enter through `setpriv` with UID 0 and all GID/group
  fields equal to the agent GID; each hook validates that identity, the helper capability mask,
  no-new-privileges and seccomp state. This makes parent FD observation use matching procfs
  credentials without `CAP_SYS_PTRACE`. The hook then requires every parent pidfd fdinfo `Pid` and
  `NSpid` to equal the one direct child, all pidfds to identify one kernel object, every retained
  numeric proc directory to identify that child, and every foreign netns FD to identify one
  distinct namespace. Parent-owned process-directory and namespace pins are duplicated to hook FDs
  8 and 7. Descriptor-relative starttime/status brackets require exact PID, PPid, NSpid,
  single-thread state, dedicated credentials, empty groups, NNP, seccomp/filter count and worker
  capability masks around the WireGuard readback. After Destroy, the pinned proc directory must
  expose no `stat` or `status`, the parent must retain no pidfd/proc-dir/foreign-netns custody, and
  the pinned namespace must contain no WireGuard object before observer closure. The root-owned
  setgid proof directory keeps every mode-0600 artifact root:root. The post-hook command remains a
  source contract plus exact self-status check rather than a separately typed PID-1 readback. A
  fresh exact-main KVM PASS remained required at that revision. The subsequent
  [exact-main run 33294974441](https://github.com/VOLPAROSSA/volparossa/actions/runs/33294974441)
  at `77b60aed3c39ba0c80d3e2dac2b9817fd6d7be2f` succeeded and retained helper-boundary artifact
  [9727163813](https://github.com/VOLPAROSSA/volparossa/actions/runs/33294974441/artifacts/9727163813).
  That evidence covers the Client-only singleton lifecycle, dedicated worker boundary and
  enumerated host-state fences at that exact revision. The subsequent
  [exact-main run 33296892632](https://github.com/VOLPAROSSA/volparossa/actions/runs/33296892632)
  at `1ca51fe0d2a2be855adb182e85c229d1d12bc017` succeeded and retained the Exit-expanded
  helper-boundary artifact
  [9727739271](https://github.com/VOLPAROSSA/volparossa/actions/runs/33296892632/artifacts/9727739271).
  [Exact-main run 33301595311](https://github.com/VOLPAROSSA/volparossa/actions/runs/33301595311)
  at `0095b113e450a0ab29da853fafa53b2b130f05fc` subsequently retained the Relay-pair artifact
  [9729172274](https://github.com/VOLPAROSSA/volparossa/actions/runs/33301595311/artifacts/9729172274).
  These three earlier results establish no forwarding, installed-package, restart,
  trusted-selection or usable-datapath readiness, and none raises the **11/100**
  score or closes AV1-09.
  Non-retained exact-head
  [run 33306523739](https://github.com/VOLPAROSSA/volparossa/actions/runs/33306523739) at
  `8d9cc533edfc1e9add273c03a9ce3fa164c3353d` subsequently exercised the production Relay pair with
  one cross-leg ICMPv6 round trip, strict growth of both nftables forwarding counters and all four
  WireGuard peer views, Commit plus retry, exact cleanup and unchanged enumerated host state. That
  non-main workflow retained no PASS artifact. Exact-main
  [run 33309109220](https://github.com/VOLPAROSSA/volparossa/actions/runs/33309109220) at
  `1f3cee798787ed4673a3ba28d88931947800ca22` then reproduced this current Relay-forwarding proof and
  retained 39,915-byte artifact
  [9731470248](https://github.com/VOLPAROSSA/volparossa/actions/runs/33309109220/artifacts/9731470248),
  named `helper-boundary-evidence-1f3cee798787ed4673a3ba28d88931947800ca22` and expiring
  `2026-11-28T11:30:49Z`. Its streamed report records overall `PASS`, exact clean source SHA,
  Debian 13 amd64 (`x86_64`) with systemd 257, all 16 checks `PASS`, and identical before/after
  enumerated-host-state SHA-256
  `2209ca5e63388fe23b8bf54c072cd2be5aa289e7e68293841150bce93ff59698`. Its scope remains explicitly
  `helper_boundary_only=true`, `datapath=false`, `restart_recovery=false`,
  `acceptance_a01_a15=false`, `cleanup_owned=false`, and `installed_package=false`. It is retained
  exact-main helper-boundary evidence, not installed-package, restart, route-manager, transport,
  ingress, usable-VPN or A01--A15 evidence, and does not change the **11/100 (11%)** score.
- [ ] Agent-helper protocol is versioned, typed, length-bounded, protected by socket ownership/mode
  plus exact peer credentials, and accepts no shell/free-text/filesystem-path operations; v3 parser
  tests reject v1/v2/future versions, unknown/noncanonical input and retired v2 operations, while
  retained exact-main live-root integration evidence exists separately for the scoped Client,
  Exit and pre-forwarding Relay-pair cycles. Cross-leg forwarding now has the retained exact-main
  helper-boundary proof above, but not complete production-integration evidence.
- [ ] Helper tags 35/28 register one exact runtime-global Prepare intent and reconcile only
  an expired same-runtime lineage. HelperClient uses one authenticated stream and one absolute
  five-second budget for each Bind-plus-operation sequence; post-Prepare-write failures transfer
  exact authority to the owned route-ticket supervisor. Tag 35 now requires the context role and a
  canonical, role-complete closed lease plan projected from the same canonically ordered Prepare;
  its external wire still carries only the Unix expiries. At the first accepted intent the helper
  samples `CLOCK_BOOTTIME` before high-resolution `CLOCK_REALTIME` and freezes process-local setup
  and hard BOOTTIME deadlines. Prepare, Activate, Commit and Acquire admission, every post-backend
  commit, and expiry reaping require both the original wall deadline and frozen BOOTTIME deadline
  to remain live; exact retries reuse rather than refresh them after wall-clock rollback. The Relay
  fence's jiffies timeout and realtime cutoff fail closed across ordinary suspend or ordinary
  realtime rollback. Combined suspend plus a sufficiently large realtime rollback by an already
  compromised host root can leave a short resume race until the BOOTTIME-aware reaper obtains its
  serialized cleanup gate; compromised-host-root containment is not claimed. The KVM proof did not
  exercise suspend/resume or realtime mutation.
  The engine rejects any plan substitution before that Prepare's Pending/backend dispatch, and the
  journal has an exact fallible conversion to its existing `ClosedPlan`. The production backend now
  reconstructs the byte-equivalent `PrepareIntent` from immutable lineage plus the correlated batch,
  durably registers it before worker reservation, and retains every non-success handoff terminal in
  the coordinator. A bounded opaque selector now lets a later exact functional Destroy retrieve only
  its own unpublished terminal. A non-ambiguous registration rejection is pre-mutation and owns no
  durable key; key retention proves definite worker-admission rejection and needs no reap. Worker
  admission, registered-worker, recovery-handoff and definite custody-fence failures instead require
  exact termination, reap and complete purge of that generation before retiring the exact `Intent`
  as `Absent(NeverDispatched)`. Deadline or actor failure preserves the same affine proof for a fresh
  retry; selector/context/ownership mismatch takes nothing, and genuinely ambiguous admission or
  actor state remains retained. This path cannot publish systemd custody, open dispatch, send an
  internal worker request, or mutate network resources; exact process retirement and reap are its
  only worker-side actions. Runtime
  mismatch and missing evidence quarantine, target-only cleanup never removes
  Activated/Committed state, and exact retries re-evaluate a capped 1024-entry runtime-lifetime
  `Absent` ledger. There is no tombstone ACK; tag 28 retries exact Pending/Owned cleanup, while tag 29
  is an independent process-wide operation outside per-route reconciliation. The production server
  can dispatch the Client/Exit-singleton-or-Relay-pair functional-alpha lifecycle backend, but no
  production manager calls this path. A boot-scoped, secret-free
  canonical/CAS ownership store and actor transitions have temp-directory tests; the production
  wrapper has explicit composition and ordering tests. Production opens and locks the actor after
  fixed runtime identity/directory validation but before cleanup-token publication, stale-socket
  removal or listener bind; shutdown cleans the engine and then proves actor quiescence and joins it
  before releasing the socket. The canonical journal now persists exact `Intent`,
  `MayOwnCustody`, `MayOwnPrepare`, `CleanupConfirmed`, and `Absent` phases. Its insert,
  custody-mark, custody-bound prepare-arm, never-dispatched retirement, cleanup-confirmation, and
  manager-absence-confirmation transitions are independently exact-current-revision retry-safe
  after lost replies; persisted typed `Absent` origins prevent cross-operation acknowledgement and
  repeated executor calls. Intervening transitions and
  conflicting identity, plan, expiry, generation, anchor, descriptor identity, or reconciliation
  state fail closed without journal mutation. The new `MayOwnCustody -> MayOwnPrepare` transition
  copies only the exact already-persisted custody evidence byte-for-byte. Either custody-bound
  `MayOwnCustody` or `MayOwnPrepare` may advance to the durable `CleanupConfirmed` phase only after
  a trusted exact-record-bound proof of worker teardown and kernel cleanup; that phase preserves
  the custody evidence and has no absent origin. Only a separate exact manager-absence proof may
  then advance `CleanupConfirmed -> Absent(RecoveredMayOwn)`. There is no direct
  `MayOwnPrepare -> Absent` transition. A private single-writer actor owns the store and both
  settlement executor interfaces on one named thread, opens and retains one verified
  parent-directory descriptor, and
  trips a process-global one-shot start latch before lock creation. The latch remains set after
  startup failure or clean shutdown. The generic actor path settles every custody-bearing phase in
  two-proof order before retiring even one `Intent`; production's prior lock-held exact-set join
  now hands it a non-empty set only when every record is already `CleanupConfirmed`, no inherited
  or manager custody exists, the journal revalidates, and a fresh manager barrier plus two new
  identical complete empty snapshots mint one-shot exact-target manager-absence evidence. The
  installed general restart cleanup executor still refuses uncorrelated proofs. One separate
  startup-only control accepts an affine proof from the fixed exact-singleton reaper described
  below and can CAS an unchanged `MayOwnCustody` or `MayOwnPrepare` record to
  `CleanupConfirmed` while the actor remains `Starting` and lock-held. A separate affine
  same-runtime handle may echo only proofs already completed by the live functional backend;
  independently, the actor may settle never-dispatched `Intent` records. Admission is bounded to four
  operations plus shutdown.
  Every non-test actor entry point now requires one absolute hard deadline carried through
  admission, queueing, actor execution, reply and thread settlement. Startup rechecks it before
  filesystem/latch work and each pending record, commands recheck it after dequeue, and each
  settlement executor receives the exact supplied value. Each operation checks it before its
  executor and after the exact proof, immediately before journal mutation, so a late executor
  return cannot publish its next phase. Expired
  unstarted work is mutation-free; every late completion permanently fences admission as ambiguous,
  and shutdown cannot hide settlement ambiguity behind a weaker deadline result.
  Definite pre-rename I/O failures permit a retry only after the retained parent, exact exclusive
  lock, absent temporary entry, and durable snapshot are all re-proved; otherwise the actor is
  permanently ambiguous. Reply and thread-settlement waits are bounded, but an actor thread stuck
  inside either non-cancellable settlement executor can only be detached while retaining the journal
  lock; the process latch remains set. Clean shutdown proves the durable boundary and additionally
  requires every record to be durably `Absent`; it refuses rather than retires or settles an
  outstanding record. Each validated wire intent locally receives a fresh random 256-bit
  `OwnershipId` inside a non-`Clone` registration owner. Registration consumes it into one durable
  key. Custody marking consumes that key into `MayOwnCustody` only after persisting the complete
  worker anchor and exact role-ordered pidfd/network-namespace identities; arming consumes only that
  phase-4 token into `MayOwnPrepare` with borrowed owner-bound resources. Every error retains the
  exact affine owner which still exists. `ProductionOwnershipRuntime` may issue a cloneable typed
  Prepare handle, but remains the sole owner of actor startup, shutdown and thread settlement. The
  handle exposes exact registration, custody marking/arming and ordered same-runtime settlement, but
  no raw codec/revision, retirement, startup recovery or lifecycle authority. Production now has an
  inventory-attested pidfd/network-namespace publication caller and live clean-Destroy settlement;
  no general inherited-custody adoption, `MayOwnPrepare` cleanup executor, supported on-disk
  migration, cross-runtime tag-28 proof, or live-root forced-crash lifecycle proof exists.
  Two bounded startup cases are now production-wired. The first is a complete non-empty set
  consisting only of already durable `CleanupConfirmed` targets. Already-absent members take the prior fresh-empty
  path. Each exact-present member is prevalidated as a full set, removed once in canonical name
  order with no ancillary descriptors, and must yield two stable snapshots equal to the opaque
  predecessor minus exactly that pair. A distinct affine restart proof advances the successor; it
  cannot enter the same-runtime proof type. Mixed present/no-store state resumes partial removal.
  The final exact-empty successor, another fresh barrier/two-snapshot empty observation and locked
  journal revalidation mint one-shot full-set manager-absence evidence for the existing actor sweep.
  The cleanup executor is never invoked. Full-set validation occurs before the first CAS; partial
  CAS progress is safely retryable from the remaining `CleanupConfirmed` targets. This retires
  confirmed journal custody, but does not reap a worker, destroy a namespace, clean kernel state or
  adopt inherited custody.
  The second case is exactly one `ExactPresent + MayOwnCustody` record whose durable plan contains
  exactly one path (Client one Client lease, Exit one Exit lease, or Relay the exact
  RelayClient/RelayExit pair for the same path), whose boot ID equals the current boot and whose
  recorded helper executable device/inode equals `/proc/self/exe`. The helper retains the startup
  actor, spawn-admission guard, original pidfd and namespace owner; proves the old process pidfd
  exited and the shared service cgroup is quiescent; then self-execs only
  `/proc/self/exe --internal-restart-reaper-v1`. A bounded credential-authenticated
  `SOCK_SEQPACKET` transcript transfers exactly one journal-bound `CLONE_NEWNET` FD. The
  single-thread child joins it once, closes the FD, installs no-new-privileges plus the existing
  fork/exec/unshare/setns-denying filter, drops to the pinned worker UID/GID with only
  `CAP_NET_ADMIN`, and is independently sandbox-attested by the parent before cleanup starts.
  Client/Exit require derived WireGuard names absent, loopback down, exact-empty nftables and IPv6
  forwarding disabled. Relay requires the same derived-link/loopback baseline, IPv6 forwarding
  `all` and `default` enabled before and after, and retires only the exact restricted DROP fence (or
  accepts the exact-empty deletion-retry successor). It never deletes a WireGuard link or writes
  forwarding. Active, foreign, partial or ambiguous policy fails closed. Only a challenge-bound
  terminal proof followed by exact pidfd reap and a second shared-cgroup sample can mint the affine
  actor evidence. The actor then performs the single phase CAS; the unchanged existing
  `CleanupConfirmed` descriptor-store-removal/fresh-absence chain completes before socket bind.
  Before spawning, the parent reserves one close-on-exec FD and requires waitable default
  `SIGCHLD` plus default `SIGHUP`, `SIGINT` and `SIGTERM`; pidfd acquisition retries `EINTR` and may
  release that reserve for one
  `EMFILE`/`ENFILE` retry. If it still cannot pin the child, it sends no protocol record, closes the
  channel and polls only the retained direct `Child` under a fixed hard deadline. Normal EOF exit is
  reaped and returns an error. A stopped/stuck child, lost waitability, competing reap or timeout is
  process-fatal: fixed `exit_group(70)` terminates the helper without a core or cleanup handlers,
  publishes no socket, performs no journal CAS, and claims neither cleanup nor exact reap on that
  branch. This fail-stop relies on the already-attested and packaged systemd `Type=simple`,
  `RemainAfterExit=false`, `ExitType=main`, no additional success or forced-restart statuses,
  `Restart=on-failure`, `RestartMode=normal`, exact three-second restart delay, status-only
  `RestartPreventExitStatus={70,71}`, `KillMode=control-group`, `SendSIGKILL=yes`,
  `FinalKillSignal=SIGKILL`, exact finite 45-second `TimeoutStopUSec`, and
  `TimeoutStopFailureMode=terminate` contract for bounded whole-cgroup retirement; it never signals
  a numeric PID. Focused injection tests cover `EINTR`, both descriptor-exhaustion errors, reserve
  exhaustion and the bounded stopped-child fail-stop path in an isolated subprocess. The privileged
  acceptance runner additionally has a fixed real-image transient-unit fault path: it stops the
  exact pidfd of the real reaper before any handshake record, requires main status 70, terminal
  `Result=exit-code`, zero restarts beyond the exact restart delay, an empty retired cgroup and
  effective readback of the complete manager tuple.
  `MayOwnPrepare`, `ExactNoStoredCustody`, multiple targets, multiple paths, wrong boot/image/FD,
  failed credentials or incomplete baseline still refuse without opening the socket.
  The production non-empty restart-refusal path now owns the outer composition. It retains and
  revalidates the exact startup journal guard, holds the same opaque process-wide admission guard
  used by every worker spawn, drives the borrowing async sampler non-cancellably, and performs the
  synchronous join before releasing either guard. The manager observation retains the exact D-Bus
  unique-name owner, unit object path, current `MainPID` and nonzero 16-byte `InvocationID`; fresh
  bookends additionally require zero `ControlPID`, canonical non-root `ControlGroup`, nonzero
  `ControlGroupId`, no delegation, `ProtectControlGroupsEx=strict`, `PrivatePIDs=no`,
  `Type=simple`, `RemainAfterExit=false`, `ExitType=main`, no additional success or forced-restart
  statuses, `Restart=on-failure`, `RestartMode=normal`, exact `RestartUSec=3s`, status-only
  `RestartPreventExitStatus={70,71}`, `KillMode=control-group`,
  `SendSIGKILL=true`, `FinalKillSignal=SIGKILL`, exact finite `TimeoutStopUSec=45s`, and
  `TimeoutStopFailureMode=terminate`. The packaged helper unit now configures that
  contract, subtracts the broad `@mount` syscall set explicitly from its positive allowlist, and
  disables cgroup delegation and a private PID namespace. The pinned strict cgroup view must be
  `0::/`, cgroup2 and read-only. Its
  exact kernfs file-handle ID is obtained through a fixed audited Linux-UAPI wrapper and must equal
  systemd's `ControlGroupId`; it is not treated as an inode number. The sampler still binds exact
  pending counts, journal targets, descriptor inventories, cgroup/PID namespace identities,
  pending-target cgroup inodes, zero live/dying descendants and canonical singleton-current-MainPID
  membership across two initial, one post-manager and one synchronous-join projection. These remain
  bounded non-atomic samples. The process-local spawn guard does not exclude PID 1 migration, and
  the strict mount observation does not prove absence of an inherited writable cgroup descriptor.
  Outside the exact singleton slice, that refusal observer performs no namespace destruction,
  kernel cleanup, descriptor-store removal, journal transition or socket readiness. AV1-10 remains
  Open because retained live forced-crash/KVM recovery evidence, `MayOwnPrepare`, no-store and
  multi-target recovery are still absent; the fixed alpha score remains 11/100.
- [ ] `HelperEngine` now keeps one armed affine owner across asynchronous PLAN/CALL/COMMIT or exact
  rollback. Stable Prepare lineage is separate from rotating operation generations; every backend
  and runtime call binds exact phase/action/request/digest plus one monotonic absolute deadline.
  Adversarial fake-backend tests cover factory/poll panic, caller cancellation, missing-binding
  recovery without stale-owner substitution, overflow, completion/deadline substitution,
  `CleanupIncomplete` quarantine, shutdown correlation, and wrong/late Acquire descriptor closure
  before exact Destroy. `WorkerCoordinator` carries one absolute deadline from
  pre-PLAN admission through request, response, optional Acquire FD, liveness and COMMIT; expiry
  before PLAN leaves no state, late completion cannot commit, and a late installed FD is closed.
  This is a success/COMMIT acceptance boundary rather than a wall-clock return guarantee because
  exact-owner cleanup and scheduling may deliver the fail-closed result later.
  A successful credentialed Acquire adopts its private raw-FD owner only after exact
  PID/UID/GID, credential/FD count, ancillary, binding and deadline validation. The audited safe
  boundary uses `F_DUPFD_CLOEXEC` with minimum 3, immediately owns and verifies the duplicate's
  `FD_CLOEXEC`, consumes and closes the original, and closes the adopted `OwnedFd` if the final
  deadline check fails.
  Its separate launcher carries one absolute spawn/handshake budget, polls spawn-lock acquisition
  against that deadline, pre-arms retirement ownership before the blocking `Command::spawn`
  operation and installs any returned child into that owner before further fallible work; only the
  spawn operation itself remains non-interruptible.
  A private production lifecycle seam reserves a coordinator-local generation, retains a
  non-expiring `LifecycleOwned` shutdown fence, authenticates a passive worker under that same
  deadline, and registers it in `Starting` without dispatching any child operation. Every
  post-reservation uncertain outcome returns a non-`Clone` exact-placement owner; registration
  failure keeps its reservation visible until detached reap, and `ReapedPendingPurge` retries only
  idempotent six-index registry cleanup without signalling the process twice. If a successful
  terminal supervisor `DestroyContext` has already confirmed reap and removed that exact generation
  from all six registry locations, a separately retained affine `Registered` owner proves complete
  absence under the registry lock and settles idempotently to `ConfirmedWorkerGenerationAbsent`
  without a second signal or wait. Partial registry residue or deadline expiry fails closed with
  that owner retained for exact retry. Commit, settlement, detach and purge recheck the deadline
  immediately before mutation. Its recovery source retains
  and revalidates the exact pidfd, proc directory, boot-ID source, PID/start ticks, executable,
  cgroup namespace/root/service directory and typed network namespace. Bootstrap binds the child
  executable to the parent image and its unified cgroup to the parent service cgroup. After the
  fixed seccomp filter denies re-exec and later namespace transitions, the parent revalidates the
  protected procfs links before identity drop; post-drop it requires exact `EACCES` on both and
  seals only retained descriptors plus freshly read start-time and cgroup evidence, without
  `CAP_SYS_PTRACE`. Recovery performs full proof I/O outside the registry lock, constructs all eight
  durable Prepare-anchor fields, and then revalidates exact process identity, `Starting`, TTL and
  liveness under the same hard deadline. Only after that complete proof it duplicates a separate
  affine pidfd plus typed `CLONE_NEWNET` pair: the pidfd preserves non-retargetable task continuity
  and the namespace FD preserves the exact anonymous cleanup target. The other retained pins remain
  pre-arm proof inputs rather than restart cleanup capabilities. The pair is rechecked against the
  same durable namespace coordinates during the final pre-publication revalidation and remains
  retained in the handoff token. A private adapter implements a bounded, typed protocol for
  publishing exactly that two-descriptor shape to systemd with `FDPOLL=0`, synchronising with a
  separate barrier and accepting success only after an exact complete descriptor-store inventory
  attestation. Before its first send it also rejects the target name or either role identity already
  present anywhere in the bounded inventory, including identity reuse under another name. The
  adapter has two private non-test callers: the live-proof selector and production durable-Prepare
  supervisor. The latter is reached only through the functional backend and publishes before its
  dispatch fence opens. Ambiguous or partially
  observed publication remains fail-closed;
  it is never treated as restart custody and is not removed automatically. Each possibly sent
  publication now poisons one process-global manager-mutation gate before `sendmsg(2)` with an
  opaque typed attempt identity bound to the exact unit object path, `MainPID`, parsed notify
  endpoint, custody name and role-ordered local identities; publication and removal IDs draw from
  one monotone counter, and that identity is retained in the normal manager-may-own terminal.
  Attempt-bound and target-bound observation-only reconcilers hold that same gate and borrow the
  affine owners while they send one causal non-mutating manager barrier, require two identical
  complete bounded D-Bus inventory identity projections plus exact service properties and
  remeasure the local binding. Exact later functional Destroy invokes them for retained same-runtime
  `ManagerMayOwn` and `SupervisorDropped` terminals respectively. A distinct no-send observer proves
  absence only while the publication gate is unpoisoned. These paths can report exact
  name/identity-correlated present, exact absent, or unresolved evidence. Only an exact correlated
  stable present or absent projection consumes the selected publication poison; unresolved,
  cancellation and mismatch retain it. Their evidence types cannot arm/adopt/remove, advance the
  journal, open dispatch or authorize publication retry. A distinct exact-name removal adapter
  accepts a stable complete baseline and the
  borrowed affine custody pair, requires a fresh uncached preflight equal to that baseline, and
  remeasures the local binding before its send boundary. It poisons the shared gate immediately
  before sending exactly `FDSTOREREMOVE=1\nFDNAME=<fixed-name>` with zero `SCM_RIGHTS`, then orders
  the mutation using a separate `BARRIER=1` notification with exactly one pipe FD. Two fresh
  uncached complete post-barrier snapshots must be equal and exactly the baseline minus the named
  pair, with service identity, local binding, and every unrelated entry unchanged. Any post-boundary
  error is `ManagerMayHaveRemoved` and never authorizes a blind retry. A same-attempt reconciler may
  clear the removal poison only after that exact removed projection. An exact unchanged baseline
  instead yields affine still-present evidence for one byte-identical removal retry bound to the
  exact predecessor, target, baseline and descriptor binding. A fresh uncached preflight must still
  equal that baseline. Immediately before its send the gate rotates to a fresh monotone attempt ID
  carrying `retry_of`. Cancellation before that boundary retains the predecessor evidence;
  cancellation after it can recover only that exact successor ID and cannot resend. The retry must
  itself prove exact removal or remain poisoned for exact reconciliation. Both
  transaction kinds and both reconcilers
  hold one process-global gate from their fresh baseline/preflight read through final attestation;
  cross-kind in-flight work is serialized, either poison blocks both mutations, and wrong-kind or
  wrong-target reconciliation fails before observation. Publication reconciliation consumes only
  its selected poison after an exact correlated stable present or absent projection; unresolved,
  cancellation and mismatch retain it, and no result authorizes publication retry. Same-runtime
  clean Destroy uses the publication observers before removal and the original, reconciliation and
  single correlated-retry removal APIs only between durable `CleanupConfirmed` and `Absent`; this
  does not provide restart recovery. Ambiguous spawn remains permanently fail-closed.
  Dropped/unwound lifecycle ownership is not yet recoverable. Concurrent terminal retirement may
  transiently retain a `Registered` owner while record or detached process ownership remains; after
  confirmed reap and complete six-index purge, that same owner settles without a second signal or
  wait. A private composite handoff now durably registers `Intent` before even reserving a local
  generation, authenticates one anonymous-`NEWNET` child as an exact passive `Starting` worker, and
  atomically installs a `DurableHandoffPending` dispatch fence at registration. Normal planning
  rejects that generation before channel, in-flight, cache, tombstone, or phase mutation. The seam
  revalidates the complete recovery anchor, obtains exact role-ordered pidfd/network-namespace
  identities through the same measurement path as descriptor-store publication, fences the
  deadline again, and durably advances `Intent -> MayOwnCustody`. Only that affine phase-4 token may
  derive one domain-separated deterministic custody name and create a publication owner carrying
  the original absolute deadline, registered worker, recovery pins, pidfd and network-namespace FD.
  It does not publish. A separate synchronous transition fences that same deadline before
  and after exact role-ordered name/descriptor attestation, revalidates the complete worker recovery
  identity once more, checks the worker/token context before mutation, and only then advances
  `MayOwnCustody -> MayOwnPrepare`. A private production activation-fenced supervisor synchronously
  takes the complete phase-4 publication owner before its first publisher poll, registers bounded
  capacity and terminal storage before activation, and performs at most one descriptor-store
  publication attempt without retry. Once its blocking closure has activated and begun running,
  Tokio cannot abort it; a queued cancellation instead stores the unpublished owner as
  `SupervisorDropped`. It retains `BeforeSend`, `ManagerMayOwn`,
  explicit post-attestation failure or queued-abort authority as unresolved and stores every success
  or failure terminal before notifying a waiter. While the guard owns an unpublished phase-4 owner,
  an unwind stores target-correlated `SupervisorDropped`; exact later Destroy uses the current
  poisoned target when one exists, or requires exact no-send absence when the gate proves no attempt
  occurred. Successful publication first transitions that same affine guard to
  `Published { publication, attestation }`; an unwind at that seam stores exact post-attestation
  unresolved custody for attested removal. Only after the pair is extracted into arming does an
  unwind abort fail-closed rather than falsely claiming an in-memory terminal. Dynamic tests cover
  success, both adapter failure classes without retry, waiter cancellation, activated outer-runtime
  shutdown, queued abort without publisher polling, the deterministic successful-publication unwind
  seam and exact later settlement, shutdown-start rejection, completion observability and zero child
  request bytes. The
  implementation itself orders authoritative terminal storage before the completion send. The
  functional backend consumes only an exact successful terminal, revalidates the worker once more,
  atomically opens that generation's pending fence, and derives all live link owners from the
  durable token before issuing a child or kernel mutation. Every other terminal, including the
  definitive unpublished handoff failures described above, remains retained until exact
  context-and-durable-ownership Destroy selects it; incomplete settlement stays retained and
  prevents falsely confirmed shutdown.

  Production publication, retained post-custody terminal reconciliation and clean same-runtime
  removal are connected only through the functional backend. Startup separately performs a
  record-transition-free, lock-held exact-set
  classification of durable journal targets, affinely inherited custody and a barrier-ordered
  stable manager inventory before any `Intent` mutation. There remains no general inherited
  adoption or broad inherited namespace/kernel cleanup executor. Only an all-`CleanupConfirmed`
  set or the exact single-path `ExactPresent + MayOwnCustody` reaper case above can proceed; every
  other non-empty classification continues to block startup. Its production refusal observer waits
  for exact inherited process-pidfd `POLLIN` under one hard deadline, permits `POLLHUP` only with
  `POLLIN`, remeasures the exact descriptor binding before and after each wait, and remeasures the
  complete pending set once more before constructing evidence. Process/thread-group interpretation
  relies on the private causal publication path creating pidfds with `PidfdFlags::empty()`; pidfs
  typing alone cannot recover `PIDFD_THREAD` flag history after restart. Every pending
  `MayOwnCustody`/`MayOwnPrepare` target must have exact inherited custody before any wait;
  `CleanupConfirmed` targets are skipped. Both success and failure retain the complete affine set.
  Only the role-ordered descriptor binding and network-namespace portion of the recovery anchor are
  freshly remeasured; the other complete anchor fields remain correlation from the previously
  lock-held projection and are not freshly journal-revalidated. A future settlement must retain and
  revalidate that exact startup guard across the wait or freshly rejoin journal and manager
  evidence. This proves one exact worker thread group's exit, not descendant exit, cgroup
  emptiness, namespace destruction, kernel cleanup, manager removal or journal settlement. The
  durable settlement substrate plus the exact singleton reaper still does not make crash cleanup
  production-complete: AV1-10 remains Open, the fixed alpha score remains **11/100 (11%)**, and this
  slice adds no scorecard, datapath or acceptance points without live forced-crash evidence.
  Shutdown uses attempt-correlated `Pending`/`Retryable`/`Confirmed`/terminal-`Unresolved` states:
  an expired new attempt returns `Retryable` without changing state, orderly timeout retains exact
  workers and handles for a later upgrade, and a waiter accepts only completion published strictly
  before its own deadline, while runtime/task cancellation fails closed and cannot upgrade.
  Terminal unresolved settlement atomically drains captured owners and immediately escalates any
  later owner instead of leaving it stranded.
  The authenticated child now executes exact Client/Exit-singleton-or-Relay-pair WireGuard Prepare,
  Activate, Probe/Commit and Destroy against its worker-local `NamespaceKernel`: interface and
  `/128` are derived from the bound
  context/path/role, the ephemeral X25519 private key stays in worker-owned secret containers that
  zeroize on drop, and only correlated kernel proof supplies the returned public key and port.
  Prepare failure becomes a normal kernel error only after exact delete and absence proof;
  otherwise resource/key state is retained as `CleanupIncomplete` for Destroy. Client activation
  consumes only the helper-projected verified relay-client peer. Exit activation first requires its
  prepared key, `DirectAssigned` underlay and listen port to equal the dual-signed exit endpoint and
  then consumes only the helper-projected relay-signed relay-exit peer. Relay atomically binds the
  complete prepared pair to the signed request/grant endpoints, installs only the client-request and
  nested exit-signed peers on their respective roles, and rolls back both links on any partial
  Prepare or Activate failure. Before either Relay link exists, the child creates a generation-pinned
  empty policy-drop baseline; Relay Activate atomically installs the exact two-direction fence,
  singleton timeout, realtime cutoff and terminal drop. Each lease installs its derived `/128` route,
  retains the readback counters as its activation baseline, and returns only after exact readback.
  Probe/Commit re-proves every exact peer and route, requires every handshake to be no older than
  activation plus strict RX and TX growth and, for Relay, requires both forwarding counters to grow.
  Only then does it commit the complete singleton or pair. Relay Destroy restores policy-drop and
  proves fence absence before link deletion and baseline retirement. Internal worker protocol v4
  makes the canonical role-complete `PrepareLeases` plan mandatory at `Initialise` and stages its
  exact derived resources before namespace-kernel access or any parent birth-link mutation. Destroy
  without an adopted lease deletes and proves that complete staged set absent inside the pinned
  child namespace before Relay baseline retirement; partial cleanup stays retryable, and only a
  pre-birth context-level `NotFound` with every birth flag false can count as cleanup evidence.
  A durable `Initialise` whose response misses the original deadline enters a cleanup-only phase
  without terminating the authenticated child. The coordinator retains only that exact canonical
  request; a later Destroy has a separate caller deadline and may drain at most one fully
  credential-, request-, digest- and outcome-correlated descriptor-free late response. It never
  replays `Initialise`, rejects duplicate, foreign and cross-context records, and does not promote a
  genuinely lost Destroy response to cleanup evidence.
  Successful internal Prepare,
  Activate, Probe and MPTCP endpoint responses must preserve exact request order and identity;
  each credentialed request now carries the parent's fixed absolute Linux `CLOCK_MONOTONIC`
  expiry in a canonical envelope, and the child reuses a no-later projection through mutation and
  response instead of refreshing a five-second budget. The affine `MayOwnPrepare` token now has one
  canonical durable-resource projector for path, role, `/128`, expiries and ownership alias; the
  production backend now consumes it only after durable dispatch-open. The engine Prepare proof also rejects
  duplicate public keys or public endpoints before affine handles can be paired. A worker
  `CleanupIncomplete` result now
  quarantines and detaches that exact generation instead of caching an apparently stable failure.
  The kernel layer preflights a complete batch as fresh, DOWN, exact-name/alias/kind
  WireGuard links before key/address mutation, and has exact-owned delete plus absence proof.
  Validated journal records now deterministically project non-`Clone` per-link resources whose
  public `ownership-v1` marker commits the immutable ownership-record fields, closed plan, and exact
  resource identity without exposing raw ownership coordinates. Mutable lifecycle evidence does
  not change it. Owner-sensitive kernel entry points accept only that typed resource and reject any
  non-exact marker. The underlay parser independently enforces exact helper grammar and interface
  binding and rejects malformed, legacy, or mismatched helper aliases in pure tests. The marker is
  evidence rather than current journal-phase or cleanup authority.
  The production server now installs a crate-private functional-alpha backend for exactly one live
  context containing exactly one matching-role Client/Exit lease or the ordered Relay endpoint
  pair. Before mutation it selects one
  consistent direct underlay through bounded read-only state, then opens a process-owned
  coordinator, initializes the authenticated child, exclusively creates the helper-derived
  WireGuard birth link under a separate non-cloneable live owner at one deterministic high
  ifindex in the parent, proves the provisional DOWN name/kind identity, sets and re-proves the
  exact durable alias by that retained index, and moves it without renumbering into the pinned
  child `NEWNET`. The outer deadline reserves separate response-reconciliation and cleanup tails.
  Child Prepare supplies only the
  correlated kernel public key/port proof; the response adds the selected direct-underlay IP.
  The engine maps `CommitLeaseBatch` to the child's exact Probe/Commit, independently revalidates
  the returned lease proof plus both Relay forwarding counters where applicable, and caches the
  exact successful committed receipt for identical retries. Destroy dispatches the exact child
  operation, including Relay policy-drop/fence-absence cleanup, and confirms worker termination,
  reap and registry purge before success. A server-owned driver schedules cancellation-safe exact expiry cleanup once
  per second without waiting for another agent request; execution is serialized behind earlier
  operations. It immediately retries cleanup-pending orphan preparations once it owns that gate,
  retries quarantined lineages on later ticks, and makes unexpected driver exit fatal. It is stopped
  and joined before engine shutdown; shutdown succeeds only for empty backend state plus confirmed
  coordinator cleanup. The public `HelperEngine::new` remains fully `Unavailable`.
  This narrow backend additionally verifies one exact canonical nested relay/exit grant against a
  bounded process-lifetime replay cache before Activate and checks both signer-derived Peer IDs plus
  helper-owned context/path/role/expiry scope. Relay also verifies the outer client-session-signed
  request, its embedded signed ClientSessionCapability and ExitReservation, the relay grant's
  SHA-256 commitment to the exact request bytes, and full capability/exit/authorization scope. All
  five signed records are admitted or rolled back as one replay transaction before mutation. Client
  binds its prepared key and installs/read-backs
  only the signed relay-client endpoint. Exit binds all three prepared local endpoint fields to the
  dual-signed exit endpoint and installs/read-backs only the relay-signed relay-exit endpoint. Relay
  binds both prepared local tuples to the relay-signed endpoints, installs only the client-signed
  and nested exit-signed peers on their respective roles, and activates the exact helper-derived
  forwarding fence. Every lease uses only its derived `/128` route; Relay Commit additionally
  requires both forwarding counters to grow and Destroy restores policy-drop and proves fence
  absence. Pure pre-mutation binding failures roll back
  replay admission; no replay entry is rolled back once worker mutation may have begun. It still has
  only the narrow committed Client/Exit unconnected-QUIC-UDP descriptor handoff described below,
  with no transport caller, ingress or usable datapath operation. It now has same-runtime durable
  journal/systemd custody, but no restart-persistent replay, independent discovery/connection trust anchor, trusted
  selected-operator authority or crash/restart recovery.
  The Client-only KVM producer exercises the no-argument server, signed activation, a temporary
  relay-side WireGuard peer, bounded ICMPv6, recent-handshake and strict bidirectional counter proof,
  exact fixture removal, exact Commit plus byte-identical cached retry and exact/idempotent Destroy;
  run 33294974441 retained that scoped exact-main evidence. Run 33296892632 at
  `1ca51fe0d2a2be855adb182e85c229d1d12bc017` retained the fresh Exit worker/namespace,
  dual-signed local tuple, relay-signed relay-exit peer, separate `vpre0` relay-to-exit leg, bounded
  ICMPv6, Probe/Commit retry and cleanup as artifact 9727739271. Relay-pair run 33301595311 at
  `0095b113e450a0ab29da853fafa53b2b130f05fc` retained the simultaneous two-endpoint worker proof as
  artifact 9729172274. That retained result is not a cross-leg route or Relay-forwarding proof.
  Non-retained run 33306523739 at `8d9cc533edfc1e9add273c03a9ce3fa164c3353d` subsequently proved
  the current isolated cross-leg fence, traffic, correlated counters, Commit retry and cleanup, but
  retained no artifact. Exact-main run 33309109220 at
  `1f3cee798787ed4673a3ba28d88931947800ca22` reproduced that scoped proof and retained artifact
  9731470248; its explicit scope is helper-boundary only, not a production route or acceptance
  result. The next exact-head helper-boundary contract now requires each Client, Exit and Relay
  lifecycle to expose exactly one role-complete staged plan, an active systemd FD-store pair with
  counts `[2, 2, 2]`, byte-exact pidfd/network-namespace identities including normalized status
  flags, settled counts `[0, 0, 0]`, and exactly three stable `Absent(RecoveredMayOwn)` journal
  tombstones with no recovery or reconciliation evidence: Client path 1 `[Client]`, Relay path 1
  ordered `[RelayClient, RelayExit]`, and Exit path 1 `[Exit]`. Two canonical journal reads must be
  byte-identical and `.next` absent. This is an 18-check contract; historical retained run
  33309109220 proved only its older 16-check form. Exact-main
  [run 33318629099](https://github.com/VOLPAROSSA/volparossa/actions/runs/33318629099) at
  `63e405119ca1266499fef145fbeff7348cef5562` subsequently proved the expanded contract and retained
  40,476-byte
  [artifact 9734273695](https://github.com/VOLPAROSSA/volparossa/actions/runs/33318629099/artifacts/9734273695),
  named `helper-boundary-evidence-63e405119ca1266499fef145fbeff7348cef5562` and expiring
  `2026-11-28T15:04:58Z`. The locally validated report records overall `PASS`, all 18 checks
  `PASS`, exact clean source, Debian 13 amd64 (`x86_64`) with systemd 257, and equal before/after
  enumerated-host-state SHA-256
  `736dc4eafc5832c672a7366978a0f18f69c47db1f2087f132bbee3dc17afd043`. Its scope is explicitly
  `helper_boundary_only=true`, `acceptance_a01_a15=false`, `datapath=false`,
  `cleanup_owned=false`, `installed_package=false`, and `restart_recovery=false`. This proves only
  the scoped helper boundary, not an installed package, shipped restart, route manager, transport,
  ingress, usable VPN, cleanup ownership, datapath, or A01--A15 acceptance. Restart-persistent
  durable recovery and the separate Add/Remove
  MPTCP endpoint seam remain required;
  AV1-09, AV1-10 and AV1-11, the **11/100 (11%)** score, and every datapath or A01--A15 acceptance
  checkbox remain unchanged.
- [ ] Root-owned Unix socket permissions and peer credential checks are enforced.
- [ ] systemd services use minimum capabilities and restrictive sandboxing; the shipped helper unit
  and doctor contract now require exactly the reviewed seven-capability bootstrap set
  (`CAP_KILL`, `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_SETGID`, `CAP_SETPCAP`, `CAP_SETUID`,
  `CAP_SYS_ADMIN`) and
  reject capabilities outside that set. The doctor also binds the agent's exact supplementary group,
  the helper's closed TUN-only device policy, every service's exact writable/read-only path set,
  and rejects repeated capability, address-family, group, device, or path directives. The helper
  contract further requires
  `LimitCORE=0`, `NotifyAccess=main`, a 128-entry
  descriptor store (two descriptors for each of at most 64 workers), preserve that store while the
  unit is retained, and explicitly keep control-group kill escalation. Before tracing or Tokio, a
  separate executable-entry crate performs the only explicit unsafe helper-startup assertion. Its
  one-shot audited raw-FD boundary latches before reading the exact activation tuple, validates the
  current PID and a positive count of at most 128, reserves and preflights the complete contiguous
  range beginning at fd 3, seals it `CLOEXEC`, removes all three `LISTEN_*` variables, and takes the
  original slots directly into affine Rust ownership without duplication. Exact absence returns an
  opaque empty proof token. The helper library remains `unsafe_code = "forbid"`, consumes that token,
  and requires an even count plus exact fixed names. Each two-entry opaque-name group must then
  canonicalise, independent of input order, to exactly one `PID_FS_MAGIC` pidfd and one typed
  `CLONE_NEWNET` namespace owner. Repeated
  kernel-object identity within or across names fails closed even when mutable descriptor status
  flags differ.
  Production opens a record-transition-free journal preflight and, under its retained exclusive
  lock, projects every custody-bound `MayOwnCustody`/`MayOwnPrepare`/`CleanupConfirmed` record before
  any `Intent` sweep. Creating the fixed lock entry is expected; no main-journal transition occurs. One
  non-mutating manager barrier then precedes two identical uncached complete bounded D-Bus
  inventory identity projections plus exact service properties. Local bindings are measured before
  and after observation; the journal parent, lock entry, held lock, absent temporary entry and exact
  durable snapshot are revalidated before a final local measurement and exact classification.
  Manager and inherited maps must be identical and every present pair must match exactly one
  derived journal name and role binding. `MayOwnPrepare` must be exactly present. An absent
  `MayOwnCustody` becomes only `ExactNoStoredCustody`; an absent `CleanupConfirmed` receives the
  distinct `CleanupConfirmedNoStoredCustody` disposition. Neither initial disposition is an
  `Absent` proof or mutation authority, and the former cannot substitute for either durable
  settlement proof. An all-cleanup-confirmed set is revalidated as a whole. Exact-present pairs are
  removed canonically through one descriptorless send and exact predecessor-minus-pair successor;
  present+no-store mixtures resume partial removal. A final fresh manager barrier and two new stable
  exact-empty snapshots precede one-shot exact-target manager-absence evidence for the existing
  actor sweep. Full-set validation precedes both the first removal send and the first per-record
  CAS; a crash after partial exact progress leaves retryable present+no-store or
  `Absent + CleanupConfirmed` state. The exact single-path, exact-present `MayOwnCustody` shape may
  take the fixed attested reaper path described above; every other `MayOwn`, wrong-phase, changed,
  missing, duplicate, overlapping, deadline or observation-failure case still refuses startup
  before cleanup token or socket publication. Dropping a refused set closes the exact process-local source
  slots; source ownership and the read-only exact-set join are no longer positive-adoption
  blockers, but general custody-capable restart cleanup remains absent. The
  production durable-Prepare publisher sends only an exact two-FD `FDSTORE=1` notification with one fixed-shape
  opaque name and `FDPOLL=0`, then a separate one-FD barrier; it can report success only when bounded
  pre/post counts and the complete systemd v257 descriptor-store dump prove the expected multiset.
  Every publication failure returned after the first send is manager-may-own and leaves the shared
  manager-mutation gate permanently poisoned. Same-runtime exact Destroy production-wires
  observation after worker reap and durable `CleanupConfirmed`: normal `ManagerMayOwn` uses its
  exact poisoned attempt, while unpublished `SupervisorDropped` uses the exact currently poisoned
  target or, only when no publication poison exists, the distinct no-send absence observer. A
  successful-publication unwind instead retains its exact attestation for removal. Attempt- and
  target-bound observation require a barrier, two identical complete bounded inventory identity
  projections, exact service properties and retained-binding revalidation; their private evidence
  grants no mutation, adoption, arming or publication-retry authority. A
  distinct remover takes a fresh exact preflight from a stable complete baseline, rechecks
  the local pair, then sends exact-name `FDSTOREREMOVE=1` with zero ancillary FDs and orders it with
  a separate one-FD barrier. It accepts only two equal fresh uncached snapshots proving the exact
  baseline-minus-pair result with unrelated entries unchanged. That same gate is poisoned
  immediately before the send; any later failure is manager-may-have-removed and no blind retry is
  authorized. Exact-still-present reconciliation retains the poison but yields affine authority for
  exactly one byte-identical retry bound to the predecessor, target, baseline and descriptor
  binding. A fresh uncached preflight must equal that baseline before the gate can rotate to one
  correlated successor attempt; cancellation cannot turn either ID into a second send. Publication
  and removal
  use distinct typed attempt IDs from one monotone sequence, cross-kind work and poison block before
  inventory I/O, and only exact-removed original- or retry-attempt reconciliation reopens ambiguous
  removal poison.
  Publication is reachable only from the private live-proof selector and production durable-Prepare
  supervisor. Publication observation, exact removal and correlated removal reconciliation are
  reached only by same-runtime exact Destroy of a retained post-custody terminal. The distinct
  complete startup observer and journal/inherited classifier are production-wired but grant no
  mutation, adoption, arming or cleanup authority. The live composition has no recorded
  transient-unit acceptance result. This is
  fail-closed same-runtime custody and clean settlement plus a read-only `MayOwn` restart boundary
  and narrow already-cleanup-confirmed tombstone retirement, not production adoption, restart
  reaping, or crash cleanup. The child
  independently disables process dumpability after parent attestation and before Ready. The component-only transient driver
  exists and the production-server phase of the committed disposable driver now exercises one normal
  functional worker lifetime. Staged-package validation remains outstanding. Exact-main Debian 13
  helper-boundary run 33318629099 retains the scoped 18-check PASS described below, and the final
  worker proof permits only `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`.
- [ ] Helper crash/termination cleanup is idempotent and complete; fake-backend reaper/quarantine
  tests prove bounded timeout retry and process-fatal signal/wait errors without false reap evidence,
  and the disposable production-server gate covers normal exact Destroy, worker reap/purge and
  namespace/link release. Forced helper crash/termination cleanup and restart recovery remain
  without live evidence.
- [ ] Namespace-local MPTCP/QUIC sockets use typed tag-27 `AcquireTransportSocket` and exactly-one CLOEXEC `SCM_RIGHTS` framing; canonical binding, correlation, close-on-reject and consuming credentialed-FD-to-`OwnedFd` adoption tests pass, including audited minimum-3 `F_DUPFD_CLOEXEC`, CLOEXEC readback and original closure. Internal protocol v4 consumes and drops the worker source before an exact credentialed release record, while missing/wrong/late release closes the adopted FD. Acquire duplicates the already attested worker namespace pin affinely before this request's tombstone/in-flight mutation, retains it across concurrent retirement without probing a process under the registry lock, and the consuming parent validator independently verifies both the complete socket shape and exact `SIOCGSKNS` nsfs device/inode identity before registry COMMIT. Post-PLAN mismatch, validation failure or expiry closes the descriptor and quarantines the generation. The production functional backend now accepts only a complete live committed Client/Exit singleton lineage with exact role, path and worker-derived overlay address. It invokes unconnected QUIC UDP for either role, connected `IPPROTO_MPTCP` only for Client, or an `IPPROTO_MPTCP` listener only for Exit in the authenticated namespace child, and transfers one validated descriptor without ordinary-TCP fallback. Once backend validation and engine COMMIT succeed, each outer request is recorded descriptorlessly in a bounded same-helper-runtime context-generation request-ID/digest ledger before response/FD delivery can be known. A same-ID/digest retry calls no backend and returns descriptorless `TRANSPORT_SOCKET_ALREADY_ACQUIRED`, including after ambiguous delivery; digest substitution conflicts, and only confirmed Destroy purges the generation. A fresh request ID can acquire again for the same context/path/role, so a future caller must authorize and bound every association. Acquire-ledger saturation does not restrict Destroy, and the worker registry reserves its final tombstone slot for terminal Destroy before admitting nonterminal operations. Unit tests cover exact Client/Exit lease projection, binding/role/path/address/phase mismatch, Relay refusal, worker error, rejected-descriptor closure, cancellation and channel ambiguity. A disposable user/network namespace smoke additionally creates both committed MPTCP descriptors and proves the returned Client FD negotiated MPTCP through the returned Exit listener with `MPTCP_INFO`. An agent/runtime caller, live WireGuard-route adoption, multiple proven subflows and datapath evidence remain absent; Relay application transport acquisition remains intentionally forbidden, so this row and the alpha score remain open.
- Update (superseding the final status sentence above): the production helper now accepts bounded multi-path Client/Exit lease batches, and the agent has a typed consumer for an acquired MPTCP Client FD. Exact committed Client endpoints reach the kernel path manager in the owning worker namespace. A separate disposable two-relay namespace smoke proves two genuine subflows both carry data. The remaining gap is composing that consumer, helper-owned WireGuard links and Exit address signalling in one acceptance route; therefore this row remains open.
- [ ] Native MPQUIC API v6 preflights an exact role/process lifetime, targets every later operation to that instance, requires nonce plus canonical-request digest response correlation, and consumes exactly one operation-bound UDP descriptor for `AddPath` or `StartExitSession` and zero otherwise. Start requests bind reservation/finalize IDs derived from the signed scope, bearer commitment, certificate digest, and both process instances; Rust and C share exact request/descriptor hash vectors and independently reject bearer/commitment mismatch. Native samples BOOTTIME before REALTIME, maintains a monotone wall floor, converts accepted wall expiry once to a BOOTTIME deadline, and fails closed on clock failure, regression, or overflow. A fixed 128-record process-local ledger has no live eviction, rejects exact pair replay and half-key scope reuse, permits only byte-identical live client retries, and tombstones stop, expiry, and every admitted Exit authorization, including backend failure. Rust and two independent C boundaries enforce server `10.76.0.1/32`, client `10.76.0.2/32` through `10.76.0.254/32`, optional client `fd76:6f6c:7062::2/112` through `fd76:6f6c:7062::fe/112`, and MTU 1280--1420. The native client deep-copies one assignment, permits only an identical active duplicate, exposes it only after `ESTABLISHED`, enforces outbound source and reverse-destination ownership, and wipes it on fatal transport failure. The Exit runtime now retains exact distinct path/listener/client tuples and caller-owned route FDs, remains pending below two paths, starts the pinned mqvpn server only when the requested multipath set is present, feeds xquic each packet's exact local tuple, and sends each native path through the matching retained FD without single-path fallback. Rust returns a non-cloneable verified Exit endpoint and binds it to the exact helper descriptor, Relay grant hash, route, path, overlay tuple, and Exit process instance before admitting a committed client MPQUIC path. Focused C tests cover a two-listener start/send/stop lifecycle; the patched pinned mqvpn library and complete native daemon compile. The row remains open: no disposable Relay/WireGuard topology yet proves two data-carrying native paths or browser QUIC/MASQUE traffic. Native still does not verify the signed bundle, cache general request nonces, or retain ledger state across restart; production also lacks the live provider-side authority call, separate role service identities/sockets, exact helper-derived millisecond-to-trusted-interval conversion, a fixed independent Rust/C DER-SPKI vector, parser fuzzing, server-side pool allocation/uniqueness/lifetime binding plus exact-namespace assigned-address proof, disposable-topology evidence, and trusted helper provenance.
- Update: exact MPQUIC activation framing now binds the signed Exit reservation, every committed
  Relay reservation/confirmation/receipt, the route context, both native process incarnations and the
  complete ordered path set. A preflighted production Client consumes one helper-owned QUIC UDP FD
  for each committed WireGuard Relay path and passes all of them to the pinned native multipath
  process. Its browser-datagram API rechecks the exact signed policy destination on outbound and
  reverse inner UDP packets; it has no direct-Exit address input or ordinary-QUIC fallback. The
  Client coordinator now HPKE-seals its retained 43-byte bearer directly to a route-owner-generated
  RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 recipient key. The Client-session-signed opaque
  delivery binds the exact reservation, route, finalization, Exit identity, TLS certificate/SPKI,
  both native instances, expiry and nonce. The Exit verifies that signature and replay state,
  correlates every field with its finalized reservation, decrypts and checks the public commitment,
  and atomically consumes the TLS/native owner. The MPQUIC activation frame carries the signed
  ciphertext; a Relay never receives the bearer plaintext. Production responder wiring still must
  pass that frame into the provider-side native `StartExitSession`, and no disposable two-path
  browser traffic has yet been proved, so this row and the alpha score remain open.
- [ ] Pre-route client ingress uses typed tags 31–34, exactly eight kind/family identities, one-shot agent acquisition, cross-unique handles/receipts, canonical exactly-one-FD binding, error-preserving RAII capabilities and retryable destroy; pure/socketpair tests pass, but production deliberately returns `Unavailable` before state/network until the namespace listener, privileged transfer cache, atomic TPROXY/DNS/kill-switch transaction, rollback and live proof exist.

## Identity and signed protocol

- [x] `volparossa init` creates an Ed25519 identity and derived libp2p Peer ID.
- [x] Private identity is encrypted at rest and created with mode `0600`.
- [ ] Session identities and WireGuard keys are ephemeral per route/path context.
- [ ] Canonical signed envelopes include version, sender, timestamp, expiry, nonce, message type, payload hash, and signature.
- [ ] Invalid signatures, unsupported versions, expired messages, replayed nonces, excessive lengths, and malformed encodings are rejected.
- [ ] Key rotation rules and compromise recovery are documented and implemented.

## Decentralised discovery

- [ ] rust-libp2p QUIC transport is integrated with Identify and Ping.
- [ ] VOLPAROSSA-specific Kademlia protocol and capability provider records are integrated.
- [ ] mDNS, AutoNAT, DCUtR/hole punching, and Circuit Relay v2 control-plane support are integrated.
- [ ] Versioned `/advertisement/4` fetches relay advertisements directly, while exit advertisements
  use only `/exit-forward/4` plus `/exit-forward-upstream/4`; the discovery crate proves the
  three-hop shape. The live single-owner agent actor now serializes policy application and
  cross-ledger revocation before reply, and linearizes freshness, current policy/authority, replay,
  and peerstore mutation in one synchronous advertisement commit before successful completion is
  cached or replied. A crate-private command can now produce a sorted, unique, at-most-200
  in-process snapshot only after production signature revalidation and exact persisted
  fingerprint/actor capability/policy joins. Expired, conflicted, self, pending-direct, unpaired,
  direct-only exit, and multiply-control-paired exit records fail closed. The discovery actor now
  builds that snapshot internally for its client-preselection owner; the snapshot has no
  serialization or dispatch authority. A separate discovery-private affine sampler then
  revalidates that exact snapshot and narrows it to one randomly selected forwarded
  Exit, its exact control Relay, and one to eight other Relays in weighted 70/20/10 high,
  diverse-middle and exploration order. It rejects malformed or ambiguous pairings, unsupported
  role/transport/family, unavailable advertised capacity, active serious faults and insufficient
  diversity before materialization; failure retains the exact original snapshot in a boxed affine
  error. It enforces strict operator, non-zero ASN and canonical public advertised `/24` or `/48`
  hint diversity, but those signed hints are not authenticated origins. A later exact-set join may
  mint only connection-derived or control-attested prefixes into private Fresh evidence; the
  existing FreshEvidence/selection hard filter must re-enforce actual network-origin diversity
  before route planning. The production discovery actor invokes the sampler before its affine
  request lineage; it never creates a direct Exit candidate, chooses no endpoint and grants no
  dispatch or Fresh-evidence authority. Control-v4 tags 17 and 18 now
  define the request/response transcript used by that control-plane owner for an actor-signed direct
  observation transcript or an exit-signed receipt nested in a control-signed public-prefix claim.
  The dedicated verifiers are transactional and return opaque affine transcripts. The actor-owned
  A1a attempt validates
  an endpoint-free reduced snapshot and local conservative ceiling, internally mints a 16-byte
  batch ID plus two to nine unique 32-byte request/challenged-relay-or-exit challenges (the control
  shares the exit challenge), and retains one forwarded response plus one to eight direct-relay
  responses as three to ten opaque signed-envelope proofs. It allows only one
  JIT pending request, uses fixed 5-second request/30-second attempt/30-second cooldown windows,
  120-second challenge and batch tombstones (36+4), and a 40-entry replay cache without redraw,
  retry, or live eviction. On pre-entropy rejection `PreselectionBeginFailure` retains the original
  gate without cooldown; after admission only a valid non-decreasing terminal clock returns a
  cooling gate, while invalid/backward/overflowing time loses it fail closed. Its opaque
  `BoundPreselectionTranscriptBatch` records no authenticated
  connection/socket, send/arrival event, direct prefix, RTT, reachability, Fresh validity, capacity
  authority, reservation, route-session, or dispatch authority. The completed affine A1a owner
  retains the original non-cloned candidate snapshot as a sibling, never inside that endpoint-free
  transcript batch, so a later exact-set owner need not reconstruct the candidate union. Any
  advertised control endpoints in that existing actor-private snapshot never enter the transcript
  batch or opaque transport proof. Discovery now composes two role-gated v4 request-response wire
  behaviours over unchanged exact A0 canonical bytes: Client outbound/Relay inbound for direct
  Relay receipts or forwarded Exit attestations,
  and Relay outbound/Exit inbound for forwarded Exit requests and Exit receipts. Requests and
  receipts are bounded to 4096 bytes, forwarded attestations to 8192 bytes; both behaviours use an
  exact five-second timeout, 64 streams, distinct event/request-ID domains, no legacy aliases and
  no retry. Their opaque wrappers and codecs enforce only state-free canonical/version/hop
  type/role/payload/envelope shape on read and write. The client-hop and relay-to-exit service
  seams now have independent one-at-a-time slots. Each derives its target and family from the exact
  request, captures a connection witness immediately before its synchronous send, and can cancel or
  bind an opaque same-hop response arrival sealed by the originating service's private event pump,
  which stamps monotonic and wall arrival time before returning it. Upstream dispatch requires
  the forwarding control to be local and targets only the exit. Context-bound variants retain a
  non-cloned caller owner—suitable for the original candidate-snapshot attempt or downstream
  request/channel. A client transaction presented to a foreign service is retained unchanged for
  its originating service. Once that service recognizes the exact active client transaction, any
  sealed response is terminal: the slot is released before service-instance, peer, request-ID,
  half-open deadline or provenance validation, and failure recovers the exact unchanged caller context
  without reusable dispatch authority. Dropping an active token or an unavailable arrival clock
  still leaves its slot occupied. The upstream hop also retains its slot for a foreign service,
  peer or request ID; exact upstream correlation consumes it before later time or provenance
  checks. Binding rechecks the event-local connection, uniqueness, generation and native prefix.
  Dispatches, transactions, arrivals and unconsumed bound tokens expose no equality oracle,
  constructor, generic field/getter or decomposition. Purpose-specific terminal consumption
  destroys their authority and yields only an endpoint-free normalized public IPv4 `/24` or IPv6
  `/48`, sealed local wall-observation time and monotonic round trip for client transport; only the
  normalized prefix for the Relay-signed upstream wrapper; only signed validity for a direct
  transcript; or the earlier joint signed validity and control-signed normalized prefix for a
  forwarded transcript. No projection contains a request, identity, signature, nonce, full
  endpoint, connection, dispatch capability or other reusable authority. The production discovery
  owner consumes these values through the exact-set `FreshEvidenceBatch` join and returns only an
  opaque `PreparedPreselectionEvidence` handoff. Its false native-address-usability result grants no
  route readiness. Empty local `Connect` now derives one explicit operator-configured address
  family and minimum/local/conservative capacity profile, chooses the first enabled transport
  deterministically (UDP, then TCP, then browser QUIC), and invokes that actor-owned preselection
  boundary. UDP requires exactly one native path; TCP MPTCP requires the configured selection
  minimum; browser Multipath QUIC requires the greater of that minimum and its own configured
  minimum, with both multipath cases rejecting fewer than two paths or an enabled degraded
  fallback. A private affine native continuation consumes the handoff, mints its independent
  bounded candidate owner, wraps each required signed native Permit request in candidate order with
  the exact selected control-Relay and Exit lineage, and dispatches it through
  `request_exit_forward` only to that control Relay. Exact wrapper/correlation/operation/Exit checks
  and protocol verification consume each granted Permit. The affine continuation then sends each
  exact endpoint-free request/Permit pair directly to only its selected data Relay over typed
  `NativeProbeReady` framing, verifies the wrapper identity, operation, status and signed
  `NativeProbeRelayReady`, and retains the remaining candidates and shared replay state with that
  readiness. The next typed seam binds a same-connection
  helper runtime and one exact prepared Client lease into the native endpoint commitment and
  retains exact Destroy authority. It signs `NativeProbeStart` while the lease is still prepared,
  sends it only to that data Relay over the distinct `NativeProbeAuthorize` operation, and permits
  Activate only after verifying the returned standard nested Exit/Relay-signed
  `RelayReservation` against the exact Start hash, selected actors, route context, policy, prepared
  Client key, Relay endpoint and helper hard expiry. The production Exit service independently
  verifies a bounded canonical five-signature Permit-to-Start chain, current Exit boot and
  authenticated data-Relay before atomically reserving probe capacity and signing the standard
  `RelayAuthorization`; the production Relay service independently verifies it, exact-matches its
  already-prepared endpoint pair, reserves capacity, signs the nested `RelayReservation`, and
  retains the affine Start owner. A real service-composition smoke verifies that complete signed
  chain and byte-identical Exit retry. The later affine states build exact Activate/Commit requests,
  dispatch that already-authorized Start only after exact helper activation, and verify the
  correlated `NativeProbeRelayResult` together with non-zero helper commit facts.
  Production Connect repeats that exact Prepare/Authorize/Activate/Start/Commit/Result chain until
  the required count is proven, retains every proof and committed helper context affinely, and
  fails closed with agent-scoped cleanup if any later candidate or path phase fails; it never
  degrades to the first completed path. Current native grants bind each candidate to its unique
  `probe_id` route context and `path_id = 1`, so this is necessarily one helper lifecycle per path;
  one shared multi-lease helper context remains blocked on a corresponding signed
  Exit/Relay-grant generalization. Connect still returns `Unavailable` after this proof batch
  because later route admission is absent. The discovery actor still lacks the production
  Relay/Exit Ready producer and later Start/Result execution. Its Relay-to-Exit Authorize
  responder and helper-side exact native-Start activation verifier are present, but remain
  unreachable until Ready retains the prepared Relay/Exit endpoints and affine phase owner. The
  client dataplane challenge injector is also absent, so no native
  result, route admission or usable dataplane proof exists yet.
  The swarm pump rejects a still-current client-hop request unless it targets the local relay/control
  and the authenticated remote differs from the local peer and actor; requester-anonymous A0 has no
  client identity to bind. Upstream alone binds the authenticated relay exactly to
  `forwarded_control` and the actor to the local exit. These request predicates and raw response
  channels stay behind a private event pump: the ordinary public pump closes both inbound hops,
  drops stale/unowned responses and seals only the exact active response into an opaque
  instance-bound arrival, while the role-gated responder pump
  applies the same response sealing and internally consumes direct Relay and upstream Exit
  requests. No public pump yields a raw preselection request or response
  message, and no public raw-event bind, response-channel or preselection response-send API exists.
  A separate production-compiled role-gated response poll
  owner obtains each typed inbound client-hop or upstream event directly from its own swarm, so the
  behaviour-local request ID,
  response channel and `ConnectionId` cannot be transplanted across service instances. It requires
  that exact event-local authenticated `ConnectionId` and unique current native-family lineage,
  and retains the opaque affine proof until response handoff.
  It re-verifies the exact currently served local advertisement signature and local Peer/node/key,
  requires a nonzero-ASN Relay or Exit advertisement supporting the requested transport/family and the
  exact active policy version/hash/expiry, and signs the request hash, challenge, actor, scope,
  local observation time and bounded validity with the same permanent identity. The canonical v4
  envelope thereby binds sender, timestamp, expiry, fresh fallible CSPRNG nonce, message type,
  payload hash and Ed25519 signature. Exact request hashes enter a 120-second no-rollback tombstone
  before signing, with 1024 global and 16-per-authenticated-peer limits; replay, capacity
  exhaustion, signer failure, stale authority and ambiguous lineage fail closed. Real two-swarm
  tests prove that the originating direct and upstream response channels carry the exact
  role-signed receipt; companion
  transport regressions prove the public pumps expose no inbound channel and a sibling service
  cannot answer the originating service's privately captured channel. A public real-swarm proof
  binds both sealed response hops; separate independent client and upstream request-response
  behaviours deliberately reproduce the same behaviour-local outbound ID, but their real response
  cannot bind when sealed by another service. It emits no
  origin claim, RTT, capacity measurement, Fresh evidence, admission, reservation or route
  authority. For the upstream hop, the forwarded-control key and Peer ID must derive the exact
  authenticated Relay and the actor must be the exact local Exit. The production discovery actor
  now selects this private responder pump only for an immutable Relay or Exit role and an exact
  currently active threshold-verified policy snapshot, and lends
  the same actor-owned permanent identity only for the synchronous signing callback. Policy
  application cancels that poll branch before the actor can observe the next event. The responder
  still requires an exact currently served role advertisement; because production deliberately
  publishes no usable Relay/Exit capability before dataplane readiness is proved, this lifecycle
  integration emits no successful production response and makes no readiness claim yet.
  For forwarded Exit requests, that private pump now retains the original downstream canonical
  request, authenticated client peer, event-local connection, behaviour-local inbound request ID
  and response channel as one affine owner while it dispatches the unchanged bytes upstream. Only
  the exact Exit peer/request ID and still-current unique connection lineage can return. The owner
  cryptographically verifies and fixed-cache replay-admits the Exit receipt, rebinds its exact
  request hash/challenge/actor/scope/signing identity, and purpose-specifically consumes the opaque
  upstream proof into only its public `/24` or `/48`. It then re-verifies the current Relay
  advertisement, permanent Identity and active policy, signs a ceiling-minimum
  `ForwardedPreselectionAttestation` with a fresh fallible CSPRNG nonce, and answers only through
  the retained original client channel. Timeout, downstream cancellation, exact upstream failure,
  authority drift, replay, provenance, signature or channel failure drops the owner and clears its
  one upstream slot without response. The Exit replay cache has 1024 fixed entries and no live
  eviction; exact cross-binding failure rolls back only its newly inserted entry. A hermetic
  three-swarm MemoryTransport test verifies both signatures and replay protection, checks live
  connected-peer state contains the Relay but not the Exit, and exercises wrong-peer,
  wrong-request, wrong-connection, upstream/downstream failure, policy drift, deadline and
  responder-disable cleanup. The observed public `/24` comes from explicitly injected test
  endpoint lineage, not an external-network observation. Separate tests cover `/24` and `/48`
  projection, identity substitution, cross-request replay rollback, and read-only provenance
  preflight before shared replay capacity. A tentative non-cloneable tombstone token commits only
  after the synchronous dispatch succeeds and otherwise rolls back only its exact new pre-send
  record. This remains control-plane
  transcript production only and claims no Freshness, readiness, capacity, reservation, route or
  datapath.
  The production discovery actor now owns the snapshot, native-agnostic sampler, sequential affine
  request/bind lineage, exact transport join and opaque Prepared handoff. The join
  consumes the completed A1a owner plus one exact `BoundClientPreselectionTransport` per canonical
  request and purpose-consumes both opaque proof types. It rejects count, order, duplicate or wrong
  request hash, actor/role/forwarded-control shape, transport, family, wall-window and independent
  monotonic-window substitution before retaining one bounded endpoint-free record per request. The
  original candidate snapshot remains the non-cloned sibling throughout. The route-selection child
  can consume that result directly into its existing private `FreshEvidenceBatch`; no parallel
  evidence type or public constructor was added. Direct records carry the exact client-Relay prefix
  and RTT. The forwarded record carries the client-control prefix plus the exact control-signed
  upstream Exit prefix, while its RTT is explicitly the complete
  client-control-Exit-control-client request round trip, not a direct client-Exit measurement.
  This mint records one successful reachability sample, no measured p25, neutral zero proximity and
  egress-quality values, a configured non-authoritative preselection ceiling, and
  `network_address_usable = false`. Its false local-block flag means only that no blocklist hit was
  supplied, not that policy was proved. A private A1c precursor passively tracks
  authenticated libp2p establish/address-change/close lineage under the existing
  384-global/four-per-peer ceilings.
  It counts unusable siblings for uniqueness, accepts prefixes only from exact direct public-IP
  TCP or QUIC-v1 remote shapes, retains only the opaque normalized token plus the same native three
  or six prefix bytes (no full IP/multiaddress), generation-invalidates every address change, and
  permanently poisons and clears on ambiguous lineage or overflow. Its affine
  witness/binding rechecks the exact Peer ID, `ConnectionId`, non-zero generation and native /24 or
  /48. It has no generic registry/address/prefix accessor; only the purpose-specific client and
  upstream seams may consume its affine witness, and only the affine Relay wrapper may consume an
  upstream binding into the signed endpoint-free prefix. The actor invokes the exact join and Fresh
  mint, but the existing hard filter rejects their output until an actual helper-backed native-path
  sampler proves dataplane address usability. A private production-owned native attempt owner now
  consumes the exact Prepared handoff from local Connect while the five-second receipts remain live
  and mints a separate at-most-five-minute endpoint-separated client/wire/verifier/data-Relay affine
  contract. It does not extend the receipts or claim usability. A separate module-private,
  non-Clone Exit wire-phase owner can retain a Permit through one production-composed server-side
  caller. That caller validates the full forwarding scope, current exact control capability and locally
  served Exit advertisement, binds the inbound control Relay's exact libp2p connection, and
  consumes that token with the response channel. The bounded Exit ledger stores the affine owner
  before handoff and returns byte-identical output for an exact same-actor retry without re-signing.
  Relay and Exit runtimes now publish their exact signed local service advertisement and bounded
  provider indexes from explicit operator capacity, origin-hint and active-policy configuration.
  This opens the server's local-advertisement gate, but the self-declared capability remains
  untrusted preselection input and no production client Permit dispatcher reaches it end to end.
  ExitReady and ExitResult remain test-only; their authenticated data-Relay values still lack a
  production connection-owned source. Its typed
  projection from the `Copy` `ExitEndpointLease` proves no helper-resource custody,
  same-connection provenance or cleanup authority; its exact helper/datapath observation
  deliberately has no constructor. A
  production Ready/Result caller, challenge delivery, the actual sampler, helper/datapath authority
  or evidence, measured capacity/readiness, usability promotion and route admission are absent. No
  checkbox is closed. Production still publishes no usable relay/exit capability, route
  finalization still fails closed with
  `ProbeEvidenceUnavailable`, and no disposable live-network proof for the post-Permit pipeline
  exists. This closes no scorecard row; the fixed alpha score remains
  **11/100 (11%)**.
- [ ] Bootstrap from peerstore, mDNS, multiple independent built-ins, peerlinks, and signed bootstrap files works.
- [ ] No bootstrap node or DHT record becomes a unique authority or central node catalogue.
- [ ] `volparossa://peer/...` peerlinks round-trip and validate.

## Advertisements, peerstore, and reputation

- [ ] Signed advertisement schema contains the required bounded fields, and production Relay/Exit
  runtimes now sign, serve and index short-lived role advertisements with current ledger capacity
  plus explicit operator/ASN/prefix/policy claims. A live multi-node ingest proof and Fresh
  datapath evidence are still absent, so these untrusted claims do not make a route usable.
- [x] Advertisement TTL, monotonic sequence, signature, consistency, v4 protocol, active-policy,
  current-authority, and replay checks fail closed at one synchronous commit boundary.
- [ ] SQLite has bounded schema/APIs for advertisements, endpoints, reachability, path measurements,
  delivery history, uptime, failures, policy hash, and last success; the agent discovery actor
  produces advertisement/endpoint writes, but no production measurement, failure, or
  session-success producers exist.
- [x] Peerstore does not persist browsing domains or destination history.
- [ ] A tested conservative capacity primitive takes the minimum of advertised free, fresh local
  p25 when present, and a conservative preselection capacity ceiling. Snapshot projection
  deliberately omits stored endpoint/RTT/capacity history. The actor-owned exact A1 proof mint
  supplies no measured p25 and treats its configured ceiling only as a bound, while test
  observations also cover sparse exploration. Both paths bind one normalized public /24 or /48 and exact
  advertisement payload hashes. The prefix, hashes and ceiling grant no measured capacity,
  reservation or dispatch authority. Explicit validity is bounded by freshness, attempt, policy,
  advertisement and actor capability expiry. The discovery actor invokes the bridge into an opaque
  Prepared handoff. Its private native owner now consumes it from production Connect and mints
  endpoint-free cryptographic attempt states plus the first control-Relay-forwarded Permit request;
  no helper-backed sampler or helper/datapath evidence completes them. The mint
  deliberately sets dataplane address usability false, so the actor path remains at zero usable
  route candidates instead of substituting control-plane or stored evidence. A module-private,
  non-Clone Exit wire-phase owner can retain one Permit through the connection-bound,
  production-composed server responder. The local Exit-advertisement gate is now supplied by the
  normal service publisher, but no production client Permit dispatcher reaches it. Its
  `ExitEndpointLease` projection is not helper-resource custody
  or cleanup authority and its post-baseline challenge observation has no constructor.
- [ ] A bounded 70/20/10 exploration primitive and a peer-only prospective relay selector are
  tested. The latter canonically handles at most 200 candidates, returns at most eight, and applies
  strict control/exit/slate diversity without synthetic complete-path metrics. Its dormant
  prefix-native path and the source-compatible legacy full-origin adapters use one shared
  filter/scoring/band/RNG/diversity core. No production route-selection caller lets new peers
  participate yet.
- [ ] The reputation model is local and has no universal score, but production observation
  producers and the route-selection consumer are not connected.

## Policy and whitelist enforcement

- [x] Canonical manifest supports version, validity, domains/patterns, protocols/ports, explicit IPs, maintainer keys, and signatures.
- [x] Threshold verification defaults to three-of-five production maintainer signatures.
- [x] Development keys are clearly marked and rejected in production mode.
- [ ] Live policy refresh is serialized through the discovery actor and revokes mismatched
  capability and forwarding authority before reply; selection rejects mismatched exits, but
  decentralised distribution and usable relay/exit policy-hash publication are not wired.
- [x] Domain pattern matching is label-safe and raw IP fails closed unless exact-listed.
- [ ] Exit-side resolution pins approved addresses to a flow/session and defends against rebinding.
- [ ] TCP allowlist enforces hostname, port, and TLS ClientHello SNI; missing SNI, mismatch, and ECH fail closed.
- [ ] QUIC Initial parsing enforces approved hostname/SNI on UDP/443; missing verification and ECH fail closed.
- [ ] General UDP pins an approved domain/protocol/port tuple with short idle timeout.
- [ ] DNS travels through the exit; arbitrary external resolvers and physical-interface leaks are blocked.
- [ ] Rejection logs use reason codes without durable full hostnames.

## Candidate, exit, and relay selection

- [ ] Candidate pool targets approximately 200 usable peers and applies every hard filter. The
  actor now has an exact 200-entry snapshot bound, but its production usable-candidate count
  deliberately remains zero.
- [ ] Weighted candidate selection uses the specified 30/20/15/15/10/10 inputs and 70/20/10 exploration tiers.
- [ ] Exit selection occurs before relay selection and uses the specified weighted factors. A
  dormant fake-only planner now consumes an exact snapshot-bound observation batch and selects one
  exactly forwarded exit before constructing a prospective relay slate. Its conservative
  preselection capacity ceiling and normalized prefix are only test scalars and establish no offer,
  hold, reservation, admission, provenance or dispatch authority. Exact advertisement payload hashes
  bind the projected advertisement, direct/forwarded capabilities, Fresh/authenticated/verified
  records and later capability re-resolution. The production discovery owner now exact-set joins
  A1a/A1c proofs, mints the existing private Fresh batch and exposes only an opaque Prepared
  handoff. A private production-owned native attempt owner consumes it from Connect and retains
  affine endpoint-separated contracts. A module-private, non-Clone Exit wire-phase owner can retain one
  Permit from a connection-bound, production-composed server caller in a bounded idempotency ledger,
  and the current local publisher now serves the exact Exit advertisement, but normal runtime
  issuance remains fail-closed because no production client Permit dispatcher consumes the affine
  client attempt. Its
  typed `ExitEndpointLease` projection provides no helper-resource custody or cleanup authority.
  There is no production Ready/Result caller, same-helper prepared-lease provider, post-baseline
  challenge evidence producer, helper provisioning, actual sampler, measured capacity/readiness,
  datapath evidence or route admission. Its output remains deliberately unusable for selection.
- [ ] Relay selection measures and scores the complete client-relay-exit path. The second dormant
  scalar preflight stage can require complete evidence bound to the selected exit and exact relay
  snapshot, but it remains a test-only boundary and is not called or trusted by the new phase-A
  plan. The plan contains no complete-path scalars. The separate private/dormant route transaction
  now moves one session, hold and the original non-Clone-bound probe objects through an internal
  measured continuation with the same IDs and absolute deadline. Its canonical post-probe selector
  ignores pre-probe active/warm hints: any eligible measured path may satisfy the minimum, while
  additional active paths still require unique-throughput gain or failover value. A dormant
  phase-C1 boundary can consume the phase-A plan once, preserve actor-specific evidence windows,
  assign stable prospective path IDs, carry one bounded Tokio deadline and mint one route-authority
  pair plus one `ReservationSession` only after all validation. Dormant C2a/C2b prerequisites make
  the phase-B request a flat ordered list of
  explicit prospective path IDs and remove pre-probe active/warm roles; final policy counts remain
  independent, so a UDP `1/1/1` policy may probe several prospects. The bridge consumes each full
  `Candidate` into a private actor-bound proof before request construction. That proof retains exact
  batch/actor/key/sequence/payload-hash/policy/expiry/static-scope/forwarded-exit binding, an
  observed prefix and
  an opaque value-only selection projection, but no full advertisement, advertised endpoint or raw
  observed-origin IP. Request, path and proof values are non-cloneable, non-debuggable and
  non-serializable. Post-probe scoring revalidates their exact time/scope binding and uses the same
  canonical selector core as the source-compatible legacy API; successful selection consumes all
  proofs and forwards only proof-free selected actor bindings, while error retains the original
  transaction for rollback. The private unmeasured wrapper moves one caller-supplied deadline into
  the measured continuation, and the transaction no longer exposes its old resolve-and-generate
  constructor or a product session-remint call. The dormant C2c adapter now consumes the C1
  continuation under one manager task/watch, recomputes its exact actor/evidence ceilings, builds
  the sanitized request in stable path-ID order, and performs one bounded borrowed re-resolution
  through the same owned combined resolver/transport value; the adapter accepts no second handle
  between these phases. It post-checks wall time, cancellation,
  deadline, proofs and resolved capabilities—including exact advertisement payload hashes—before
  moving the original session, IDs, limits and
  unchanged deadline into `UnmeasuredRouteSetup`. Pending cancel, call timeout or handle drop ends
  before reservation dispatch with no helper/journal cleanup. Real measurement production,
  production probe verification/handling, production orchestration and a production caller remain
  absent, so the checkbox remains open.
- [ ] Path capacity is the minimum of both legs, relay free capacity, and exit reservation.
- [ ] Operator, IPv4 /24, IPv6 /48, ASN, and visible-access diversity constraints are enforced.
- [ ] Defaults select four active, at least two, at most eight, plus two warm backup paths with RTT-spread/hysteresis rules.
- [ ] A new path is activated only for meaningful unique throughput (about 10%) or failover value.
- [ ] The dormant prospective selector enforces node/Peer ID, operator, ASN and one normalized
  public IPv4 /24 or IPv6 /48 against control, exit and the slate. The fake evidence, plan and actor
  proof retain no full host IP; the legacy candidate-origin field is `None`. This limits one selected
  slot per observed cluster but does not eliminate pre-sampling Sybil identity multiplicity. The
  broader production anti-Sybil layers, age/rate policy, authenticated ConnectionId/send-arrival
  evidence and live observation producers remain incomplete. There are still zero usable production
  candidates, and this item remains open.

## Reservations and path lifecycle

- [ ] Hard-incompatible reservation/control v4 uses a fresh session key/ID and signed, bounded
  capacity-hold -> probe-permit/evidence -> exact relay-set finalize -> relay-grant -> exact
  confirmation-receipt phases; v4 wire/package types remove permanent client Peer-ID fields and
  reject v1/v2/v3/future envelopes without fallback. The hold separately binds a final path-count
  upper bound and a prospective permit limit with `1 <= maximum_paths <= probe_permit_limit <= 8`;
  protocol, coordinator, exit, relay, fixture, and agent route tests cover missing-field rejection
  and a non-contiguous 2/5/8 final subset. The migrated route coordinator remains private/dormant
  and has no production caller. Its private phase-B split returns the original transaction on a
  measurement error, rejects cancellation/deadline expiry before retirement/Prepare, and builds one
  finalize frame only after Prepare while retaining the same session/IDs/deadline. The route-level
  helper lifecycle now retains the exact Prepare plan/result and helper runtime in one non-cloneable
  owner. Fresh Activate, Commit and retirement Destroy streams bind that runtime before mutation;
  timeout/cancellation leave the owner in the existing bounded retirement/retry path. This closes
  only same-process phase correlation, not restart adoption, Ready/Result or a usable datapath. The
  route-level
  probe associated type is no longer Clone-bound, but public reservation `Verified*` values are not
  claimed to be affine and `VerifiedRelayProbe` remains cloneable for API compatibility. C2a/C2b
  admit only explicit ordered prospective IDs `1..N` (1-8 and at least the policy minimum), retain
  affine actor-bound proofs until successful post-probe selection and carry one bounded
  caller-supplied deadline from the private unmeasured wrapper through phase B; work already expired
  when wrapper execution begins fails before its first protocol, transport, retirement or helper
  event. Exact probe-ID membership is checked before capacity filtering, and later trusted time is
  checked against every proof before selection completes or helper Prepare. The private C2c seam
  now consumes the C1 pre-probe continuation into the existing transaction with the same freshly
  minted session/ID pair, stable path IDs, limits and absolute deadline after bounded actor
  re-resolution. Dropping C1 before the handoff still needs no rollback; cancelling, timing out or
  dropping a pending resolver also occurs before reservation dispatch and makes no helper or
  journal cleanup claim. No production caller invokes this seam. A separate dormant owner-first
  prerequisite can retain one already-running route handle or one established route. Its occupied
  slot returns a second handle intact but is not admission control and does not prevent that second
  task from already having dispatched. Consuming settlement keeps success established, reopens the
  slot only after `NotRequired`/`Destroyed` failure cleanup, and leaves `Quarantined` terminal.
  Consuming drain cancels and waits for pending work, immediately retires a racing late success, or
  tears down an established route; dropping the owner/future delegates to the existing handle and
  retirement RAII. It does not own/start/shut down the manager, and a future production lifecycle
  must drain it before manager shutdown. It has no production caller, so admission-before-spawn,
  production lifecycle integration and end-to-end route ownership remain incomplete.
- [ ] Every exit-facing v4 scope binds the chosen control-relay node/Peer ID, exit node/Peer ID and
  boot incarnation, policy, capacity, session key/ID, hold/finalize IDs and expiries; final bundle and
  confirmation hashes bind exact canonical frames and ordered authorizations. Finalization also
  signs only a domain-separated commitment to the affine 43-byte route bearer plus the MASQUE
  context and client-native process instance. The final exit grant signs the exact echo together
  with certificate/SPKI hashes, canonical TLS name, and exit-native instance. Client release is
  gated by the exact full confirmation-receipt path set; exit TLS ownership is separately
  zeroizing, absent from response caches, confirmation-gated, and one-shot. Release, purge, and expiry wipe pending
  ownership, and scope mismatch does not consume a legitimate retry. The discovery crate
  exposes no client-to-exit RPC; the migrated route coordinator resolves actor-minted capabilities
  and dispatches every exit phase only through the selected control relay. The coordinator remains
  private/test-only and has no live network or packet-capture proof. Its production bridge has no
  production native API-v6 preflight caller and therefore rejects before signing a hold or dispatching any
  reservation/helper operation; certificate/key consistency and native backend adoption remain
  incomplete.
- [ ] Exit/relay services reserve and roll back capacity through bounded idempotent state machines.
  Prospective permits cause no additional ledger debit; successful subset finalization clears
  unused permits and their response cache while retaining only the exact finalize retry response,
  and every finalize error leaves the held permits fail-atomically intact. Production finalize
  deliberately returns `ProbeEvidenceUnavailable` until helper-proven endpoints/readiness and a
  production two-leg, Relay-forwarded probe producer exist; neither the separate helper-boundary
  Exit fixture nor the isolated Relay branch smoke is that producer. Only an explicit test-only
  evidence verifier reaches the subsequent helper phases in service tests.
- [ ] The v3 lease API exposes only opaque handles and public endpoint material and has no private-key
  input/output. The production server's functional-alpha backend can obtain one helper-owned
  Client/Exit singleton or one exact ordered Relay endpoint pair with kernel-proven key/port and
  selected direct-underlay IP; Relay activation verifies its exact five-record signed authority
  chain. Client installs only
  its relay-client peer; Exit
  first binds the complete helper-prepared local tuple to the dual-signed exit endpoint and installs
  only its relay-signed relay-exit peer. Relay binds both prepared local tuples, installs only the
  client-request and nested exit-signed peers, and activates the exact two-direction nftables fence
  described above, with complete-pair rollback and Destroy. Every lease uses the derived `/128`
  route, retains an activation baseline, and Commit occurs only after a recent handshake and strict
  RX/TX growth for every lease; Relay Commit additionally requires both forwarding counters to grow.
  Exact-main run 33294974441
  retained the Client-only one-leg proof. Exact-main run 33296892632 at
  `1ca51fe0d2a2be855adb182e85c229d1d12bc017` retained the fresh Exit worker/namespace, separate
  `vpre0` relay-to-exit WireGuard leg, bounded ICMPv6, strict bidirectional growth, exact fixture
  cleanup, exact Commit plus byte-identical retry and exact Destroy as artifact 9727739271. The
  Relay-pair exact-main run 33301595311 at `0095b113e450a0ab29da853fafa53b2b130f05fc`
  retained the complete-pair worker proof as artifact 9729172274. Non-retained exact-head run
  33306523739 first added the scoped cross-leg forwarding proof described above; exact-main run
  33309109220 at `1f3cee798787ed4673a3ba28d88931947800ca22` reproduced it and retained artifact
  9731470248. The public
  `HelperEngine::new` remains `Unavailable`, and no production route-manager caller reaches this
  helper-internal single-path seam.
- [ ] Typed/pure/fake helper boundaries prove exact public handles, cardinality, TTL, idempotency,
  state transitions, and handshake/RX/TX proof policy. Agent route tests exercise
  prepare/activate/commit/destroy and destroy-first retirement through fake backends. The helper's
  functional-alpha backend has no production route-manager caller. Its retained Client gate proves
  one live client-to-relay WireGuard leg, and retained Exit run 33296892632 separately proves one
  relay-to-exit WireGuard leg; both include ICMPv6, recent handshake, strict RX/TX growth, Commit
  retry and normal process-owned cleanup. The older retained Relay-pair proof establishes two
  simultaneous endpoint leases, not forwarding between them; retained exact-main run 33309109220
  now proves forwarding only inside that isolated helper worker. These results still do not prove
  trusted selection/policy authority, a production Client/Relay/Exit route, transport descriptor,
  ingress, a usable end-to-end VPN/datapath, crash recovery, A01--A15 acceptance, or any increase
  from the **11/100 (11%)** alpha score.
- [ ] Service ledgers reduce internal available capacity immediately, but production publishes no
  relay/exit advertisement, so advertised free-capacity updates are not wired.
- [ ] Ledger/service tests prove that explicit expiry purging restores capacity, and the agent
  discovery runtime contains a periodic purge path; no live capacity-restoration or advertised
  free-capacity propagation proof exists.
- [ ] Path state machine implements cold, reachable, warm, active, backup, degraded, and dead.
- [ ] Passive metrics, bounded probes, hysteresis, replacement, and per-direction observations are implemented.

## WireGuard, NAT traversal, and routing

- [ ] Each path creates two separate ephemeral kernel WireGuard links: client-relay and relay-exit.
- [ ] Each path has unique route ID, path ID, keys, ULA prefix, endpoint addresses, routes, authorisation TTL, and limits.
- [ ] Product code configures WireGuard and networking through netlink/UAPI, not parsed CLI output.
- [ ] Relay nftables permits only the authorised prefixes/protocol/interfaces/time and denies host access and Internet egress.
- [ ] Dataplane traversal attempts IPv6, public IPv4, coordinated UDP endpoint punching, bounded keepalive, then rejects unsuitable paths.
- [ ] libp2p circuit relay is never an implicit WireGuard dataplane fallback.
- [ ] TPROXY namespace intercepts TCP, UDP, and DNS, recovers original destinations, excludes tunnels/control traffic, and prevents loops; typed socket and fail-closed TCP/UDP original-destination UAPI foundations have pure/socketpair tests, but no namespace/nftables transaction or live interception exists.
- [ ] Kill switch prevents physical-interface leaks while preserving explicit control/tunnel reachability.

## TCP over real MPTCP

- [ ] Transparent TCP interception feeds a streaming local proxy.
- [ ] Versioned `OPEN_TCP` framing is signed, bounded, and validated at the exit.
- [ ] Client-to-exit proxy framing is protected by TLS 1.3 while preserving the application's own byte stream/TLS.
- [ ] Proxy sockets explicitly use `IPPROTO_MPTCP`; ordinary TCP fallback is impossible by default.
- [ ] `MptcpPathManagerBackend` and the Debian 13 kernel backend now add/remove only helper-derived endpoints for exact live committed Client leases inside the owning worker namespace. The agent can adopt a helper-returned genuine MPTCP FD and request at least two distinct selected paths. A disposable four-namespace kernel smoke proves two non-fallback subflows both carry application-scale data over different relay interfaces. The final production WireGuard-route composition and matching Exit endpoint signalling remain open, so this row is not yet complete.
- [ ] Exit validates policy, resolves/pins the destination, validates visible TLS SNI, connects, and streams without message-sized buffering.
- [ ] At least two MPTCP subflows carry real data over different relay paths. Proven over two disposable routed relay namespaces; the equivalent helper-owned WireGuard acceptance topology is still required before completion.
- [ ] Bidirectional scheduling works, aggregation exceeds a single constrained path where topology permits, and relay failure preserves the application flow.

## General UDP through one relay

- [ ] Transparent UDP interception/classification and original destination recovery work; exact family-matching original-destination ancillary parsing fails closed in pure/socketpair tests, but the live transparent UDP listener and routed datapath are not connected.
- [ ] Signed flow authorisation binds a single approved destination tuple.
- [ ] QUIC DATAGRAM over MASQUE CONNECT-IP/CONNECT-UDP traverses exactly one WireGuard relay path.
- [ ] Datagram semantics, destination immutability, idle timeout, and explicit DNS policy are enforced.
- [ ] Path failure may create a new association but never leaks or silently connects directly to the exit.

## Genuine Multipath QUIC / MASQUE

- [x] Current `mp0rta/mqvpn`/xquic upstream is inspected, license/draft compatibility recorded, tests run, and an exact commit pinned.
- [x] Native integration layer is isolated behind a versioned, bounded Unix-socket API (or justified safe FFI).
- [ ] MASQUE CONNECT-IP and QUIC DATAGRAM carry original browser QUIC/IP packets.
- [ ] At least two simultaneously active outer QUIC paths bind to distinct selected WireGuard interfaces/addresses and carry real data.
- [ ] Paths can be added/removed dynamically; failover preserves the inner QUIC flow where protocol permits.
- [ ] Per-path RTT, loss, congestion window, delivery rate, queued bytes, and bytes-in-flight are reported.
- [x] The production native Multipath QUIC mode uses a dedicated swappable EDT callback over live
  RTT, in-flight queue/rate, congestion window/headroom, sendability, and loss; its deterministic
  native contract test proves both healthy paths can win while a later congested/lossy path loses.
- [ ] No duplication, FEC, or false multipath reporting exists.
- [ ] UDP/443 classification recognises valid QUIC Initial packets and policy-verifiable SNI.
- [ ] Required-multipath mode defaults to at least two paths and fails closed without an unsafe downgrade.
- [x] Native upstream and the current API-v6 sanitizer gates pass: the pinned
  graph passed 35/35 upstream and 9/9 wrapper tests under ASan+UBSan with
  bounded SIGINT/SIGTERM lifecycle smokes; the earlier recorded release
  Valgrind gate also passed.

## Logging, metrics, and operations

- [ ] Structured logs contain ephemeral session/path/error/version/aggregate fields and redact prohibited metadata/secrets.
- [ ] A local-only, label-free metrics endpoint and bounded metric registry exist, but production
  does not yet produce the required throughput, RTT, loss, session, MPTCP, or MPQUIC observations.
- [x] No external telemetry is present.
- [ ] `doctor` checks every specified kernel, tool, capability, network, route, policy, library, and clock prerequisite.
- [ ] Cleanup command is safe, scoped, previewed, and idempotent.
- [ ] Demo exercises the real local topology or clearly reports unmet prerequisites.

## Testing and fuzzing

- [ ] Unit/property tests cover canonical encoding, signatures, replay, TTL, advertisements, whitelist, route contexts, scores, diversity, capacity, reservations, framing, versions, cleanup, and configuration.
- [ ] Fuzz targets cover advertisements, policy, control messages, TCP open, UDP authorisation, QUIC classification, TLS ClientHello, and QUIC Initial parsing.
- [ ] One command builds the full disposable namespace topology in the master specification using
  veth, nftables, and `tc netem`; the unprivileged lifecycle frame/state, fixed two-endpoint spec,
  run-name, ownership-manifest, confirmation, and refusal contracts pass. A separate test-only
  runner now provisions the random run ID and original namespace identities over a dedicated
  inherited unnamed seqpacket channel while retaining separate bootstrap-control and lifecycle
  channels. It kernel- and executable-authenticates its fixed parent/child pair, rejects duplicate
  or timed-out provisioning, re-executes only its fixed image with a descriptor fence, and directly
  creates anonymous user, mount, network, and pending child PID namespaces. Before mapping, the
  outer holds a pidfd, anchored proc directory, exact user/mount/network/current-PID namespace FDs,
  an empty child-set proof, and the kernel-defined uninstantiated `pid_for_children` proof. It then
  installs and independently reads back one UID/GID mapping extent. The launcher emits its mapping
  verification but cannot spawn until the outer repeats its anchored readback and returns one
  affine `MAPPINGS_PINNED` proceed record. It subsequently creates exactly one fixed
  self-reexecuted PID 1 and upgrades the full namespace proof. PID 1
  checks its PID/PPID, mappings, credentials, namespaces, environment, cwd, task count, and
  parent-death signal; the outer independently proves its executable/selector, PID nesting,
  mappings, namespaces, empty descendant set, and sole launcher-child relation. Only after the
  outer returns its run- and PID-bound pin does PID 1 make the inherited mount tree recursively
  private and use the descriptor-based Linux mount API to attach a fixed 16 MiB, 4096-inode,
  mode-0700 tmpfs at `/run` plus a new procfs at `/proc`, both with `nosuid,nodev,noexec`.
  PID 1 retains fixed root, `/run`, and `/proc` descriptors and repeatedly binds their visible
  mount IDs to bounded mountinfo, requires no propagation relationships, and proves the exact
  PID/task set `{1}` with no child. The outer independently repeats the mount-ID, filesystem,
  capacity, ownership, PID-namespace, PID/PPID/task, and empty-child proof while PID 1 remains
  pinned. Before any child process or fallback-reaper thread exists, the outer requires exact
  default inherited HUP/INT/TERM actions, a waitable default CHLD action, and an empty inherited
  signal mask. It then blocks HUP/INT/TERM/CHLD and owns the nonblocking close-on-exec `signalfd`.
  PID 1 inherits that
  exact mask, installs fixed HUP/INT/TERM emergency handlers, and verifies them directly through
  the audited Linux-UAPI layer. The outer independently requires exact live proc masks
  (`SigBlk=0000000000014003`, `SigCgt=0000000000004443`, and no managed ignored or pending bit)
  through its retained pidfd and proc anchor. The caught mask is `0x4003` managed handlers plus
  the repository-pinned Rust 1.85.0 runtime's `0x0440` SIGBUS/SIGSEGV baseline on Debian 13 amd64,
  not a Linux ABI constant. After mount verification, PID 1 directly proves the enumerated
  read-only pre-`GO` network-readiness baseline and constructs one canonical `BOOTSTRAP_READY`
  bound to the run and its measured network, mount, and PID namespace identities. The RTNL part
  pins the down-loopback configuration, including its mutable GSO/GRO limits, and proves empty
  address, route, ordinary/proxy-neighbour, nexthop, and unexpected-qdisc object sets plus the
  exact default IPv4/IPv6 rules. Each complete observation also reads the fixed namespace-local
  `/proc/sys/net/ipv4/ip_forward` record through the retained private-proc descriptor, accepts
  only canonical `0\n` or `1\n`, and requires its procfs object identity and value to remain
  stable within that observation and to match the value authorized for the current lifecycle
  phase. A bounded read-only `NETLINK_NETFILTER` exchange requires generation 1 immediately
  before and after complete table, chain, rule, set, object, and flowtable dumps, all of which must
  be empty. This readiness proof does not claim that IPv4 forwarding is disabled and makes no
  forwarding-setting request before `GO`. These observations do not claim that every netconf or
  firewall/netfilter facility is empty. Qdisc enumeration and disposable live `ingress`/`clsact`
  rejection tests prevent such a hook from hiding behind link qdisc name `noop`; traffic-control
  classes, filters, and chains are
  not separately enumerated because this slice admits no non-baseline qdisc on which they could
  attach. Other netconf, address-label,
  neighbour-parameter, conntrack, ipset,
  NFQUEUE/NFLOG, legacy-xtables, and independent-hook state remains outside this proof. The fixed
  GET requests may cause ordinary kernel module loading but create no firewall object. A strict
  production raw-`NFNETLINK` writer and observer implement the exact lifecycle policy: one
  run-derived `inet vpl_<run_id>` table, one priority-0 `filter` base chain named `forward` with a
  drop policy, and exactly three ordered rules. The first matches only the endpoint-A-to-B IPv4
  ICMP echo-request tuple and places one inline counter immediately before `accept`; the second
  matches only its exact B-to-A echo reply and likewise places one inline counter immediately
  before `accept`; the third is unconditional and places one inline counter immediately before
  `drop`. Before packet authority is consumed, every fresh complete active-policy observation
  accepts the three typed counters only when each is exactly `packets=0` and `bytes=0`. The
  one-way fixed-ICMP counter phase cannot regain zero-counter authority. After the sole raw socket
  closes, success requires two identical complete generation-bracketed observations with
  request/reply/drop packets/bytes exactly `1/60`, `1/60`, and `0/0`; subsequent teardown retains
  only counter-agnostic deletion authority. The nftables writer's sole mutation surface is one
  bounded generation-pinned atomic install and later handle-only table deletion, with strict capped ACK binding and fresh
  complete-ruleset reconciliation after every possibly sent request. Disposable namespace tests
  exercise that production writer and prove an empty generation-1 baseline, the complete exact policy at
  generation 2, and a semantically empty ruleset at generation 3 after removal. The live fixture
  also proves its inherited canonical forwarding value byte-identical; extra or altered policy
  objects, counter values, expression order, ACKs, handles, and generation lineages fail closed.
  An isolated observation cannot prove counter stability or packet absence because nftables
  generation IDs do not bind counter updates. The integrated proof instead joins one affine send
  authority to one exact reply, two matching post-close counter observations, and exact four-veth
  link telemetry. A separate fixed, descriptor-pinned
  proc writer can establish canonical `1\n` only in PID 1's disposable parent network namespace
  and later restore the exact retained original `0\n` or `1\n` record. It requests one bounded
  two-byte write only when the target differs; an already-enabled or already-restored record is a
  freshly verified no-op. Possibly written requests retain reconciliation authority. After a
  possibly written enable, only an exact enabled readback may advance; even a return to the
  original record is indeterminate and aborts fail closed because a transient write cannot be
  excluded. Production sends only the fixed run-bound ICMPv4 request described below. It does not
  claim packet absence, packet-capture privacy, a general VPN datapath, topology readiness,
  `TOPOLOGY_READY`, A14, A15, or acceptance evidence.
  The outer accepts that actual lifecycle frame
  only after matching all three identities to its retained
  PID-1 namespace pins and repeating the live mount and signal proofs. Only then does the outer
  send one canonical `GO`. PID 1 consumes the resulting affine `MutationAuthorization` and
  immediately revalidates the complete pristine network baseline before its first write. Using
  only retained directory descriptors, the production `AuthorizedPrivateRun` transition creates
  exactly `/run/netns` and `/run/volparossa-netns-runner/<run_id>` at mode 0700 plus the two
  run-derived empty namespace slots at mode 0000. It proves the exact entry set and each retained
  object identity. One fixed PID-1 task then consumes that state into `AuthorizedNamespacePins`,
  creates two distinct network namespaces A and B, and restores its exact parent network namespace
  after each excursion. It clones each namespace into a detached nsfs mount through the audited
  `open_tree` UAPI and attaches that mount to its exact run-derived slot with `move_mount`. The
  runtime proves both published pins are `CLONE_NEWNET`, have the expected owning user namespace,
  are distinct from each other and the parent, expose the expected object and mount identities,
  and are joinable through their visible read-only pins. The bounded mountinfo proof requires the
  original baseline records unchanged plus exactly those two known mount-ID/path/nsfs/no-propagation
  additions beneath the private `/run` mount; it does not independently validate every possible
  nsfs root or option field. While visiting A and B through the visible pins, PID 1 runs the same
  complete pristine-network proof used at the lifecycle barriers and restores the exact parent
  after every visit. It then uses fixed, bounded RTNETLINK directly: exactly two `RTM_NEWLINK`
  requests with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Each request derives its parent
  name from the authorized run ID, fixes MTU 1500, TXQLEN 1000, and one TX/RX queue on both sides,
  and creates peer `eth0` directly in the exact retained target via `IFLA_NET_NS_FD`; no
  create-then-move fallback exists. The affine `AuthorizedVethPairs` state retains the target nsfs
  identities and exact observed indices. Independent parent/A/B snapshots prove the down-veth
  profiles, peer and namespace lineage, unique locally administered MACs, exact zero fresh-link
  statistics/ifmap, unchanged non-link and qdisc state, IPv4-forwarding record, and empty nftables
  baseline. PID 1 then borrows that pair owner into one affine `AuthorizedIpv4Addresses`
  sub-transaction. It sends exactly four `RTM_NEWADDR` requests with
  `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`, deriving every address, `/30` prefix,
  interface label/index, namespace identity, scope, permanent lifetime, and rollback target from
  retained authority: parent A `10.241.1.1/30`, endpoint A `10.241.1.2/30`, parent B
  `10.241.2.1/30`, and endpoint B `10.241.2.2/30`. All four veth ends initially remain down.
  Independent parent/A/B snapshots admit exactly those four address records and the four
  kernel-created local-table `/32` routes coupled to them, while requiring every other route and
  RTNL object, qdisc observation, IPv4-forwarding record, and nftables baseline to remain
  unchanged. PID 1 then sends four separate bounded `RTM_NEWLINK` requests that change only the
  IPv6 address-generation mode to `none`, with an ACK, exact readback, and a distinct four-end
  proof barrier before any link-up request. Canonical retained run, pair, namespace, and parent
  ifindex lineage then supplies the only accepted policy expectation. PID 1 atomically installs and
  freshly proves the exact generation-2 policy described above before any link-up request. With
  that drop policy active and all four ends still down at IPv6 address-generation mode `none`, PID 1
  uses the retained private-proc descriptor to establish canonical `1\n` in the fixed parent
  `ip_forward` record. An original `0\n` causes exactly one bounded two-byte write; an original
  `1\n` is freshly re-read and adopted without a write. It next
  sends four separate link-up requests and
  requires an exact converged parent/A/B observation: every end is carrier-up with `noqueue`, no
  IPv6 address exists, and the admitted route additions are exactly four IPv4 local `/32`, four
  connected `/30`, four high-broadcast `/32`, and four local-table IPv6 `ff00::/8` multicast
  routes. The bounded read-only observer retains those exact requirements while tolerating only
  temporary stable kernel snapshots during route convergence inside the same two-second absolute
  deadline. Those routes remain kernel side effects of the fixed addresses and activated links.
  After fresh exact active-state reproof, PID 1 installs exactly two endpoint routes through bounded
  raw `RTM_NEWROUTE` requests: endpoint A `10.241.2.2/32 via 10.241.1.1 dev eth0` and endpoint B
  `10.241.1.2/32 via 10.241.2.1 dev eth0`. Each request uses
  `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL` and an exact `AF_INET` `/32`, main-table,
  `RTPROT_STATIC`, universe-scope, unicast, flags-zero route header with attributes exactly
  `RTA_TABLE=254`, `RTA_DST`, `RTA_GATEWAY`, and `RTA_OIF`. The plan derives its namespace,
  destination, gateway, interface index, and both-pair lineage from retained authority. A fresh
  dump proves the parent equal to its active baseline and each endpoint equal except for its one
  authorized route; a non-exact sibling or any extra object fails closed. Route authority remains
  deletion-bound after a possibly sent request, including lost or ambiguous ACK/readback. PID 1
  next installs exactly four affine IPv4 neighbours through bounded raw `RTM_NEWNEIGH` requests,
  each with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`, `AF_INET`, `NUD_PERMANENT`,
  unicast type, flags zero, and exactly `NDA_DST`, `NDA_LLADDR`, and
  `NDA_PROTOCOL=RTPROT_STATIC`. Their canonical install order is
  parent A, parent B, endpoint A, endpoint B. The two parent records map each fixed endpoint address
  to its endpoint MAC; the two endpoint records map each fixed parent gateway to its parent MAC.
  Every address, MAC, interface index, namespace identity, and route relationship is derived from
  retained affine authority rather than caller input. Strict semantic parent/A/B snapshots require
  exactly those four records, `NDA_PROBES=0`, zero proxy-neighbour records, and no other
  configuration delta. They validate the exact `NDA_CACHEINFO` structure but exclude only its
  volatile telemetry values from equality; unknown, duplicate, malformed, non-permanent, or
  conflicting neighbour records fail closed. The generation-2 policy is freshly re-proved with all
  three counters still exactly zero around installation. With those neighbours armed, PID 1
  consumes zero-counter authority and opens one nonblocking close-on-exec raw ICMPv4 socket in
  endpoint A, bound to `eth0` and `10.241.1.2`, connected to `10.241.2.2`, and enabled for
  `IP_PKTINFO`. It issues exactly one `sendmsg`, with no retry, for one 40-byte echo request. The
  identifier is the first two canonical run-ID ASCII bytes interpreted big-endian, the sequence is
  one, and the payload is the full 32-byte canonical ASCII run ID. Before the absolute deadline,
  one bounded receive must return an exact 60-byte IPv4 reply with matching source, destination,
  receive interface, `IP_PKTINFO`, IPv4 and ICMP checksums, identifier, sequence, and full payload.
  After socket close, two identical complete generation-bracketed observations prove the
  request-accept, reply-accept, and terminal-drop counters at exactly `packets/bytes=1/60`, `1/60`,
  and `0/0`. Fresh semantic parent/A/B RTNL observations prove every veth end at exactly one RX and
  one TX packet and 74 RX and TX bytes, with every other parsed 32- and 64-bit statistic zero,
  while routes, addresses, qdiscs, all four permanent neighbours, zero probes, and zero proxy
  neighbours remain exact. PID 1 then sends explicit bounded `RTM_DELNEIGH` requests in reverse
  endpoint B, endpoint A, parent B, parent A order, reconciles every possibly sent request to exact
  absence, proves the pre-neighbour routed state restored without changing the post-echo link
  telemetry, and re-proves the exact `1/60`, `1/60`, `0/0` counter profile. It never relies on link
  deletion to remove a neighbour. No `RTM_DELROUTE` request or encoder exists. PID 1 then consumes
  the joined reply/counter/telemetry proof, converts policy ownership to counter-agnostic cleanup
  authority, and directly deletes veth B followed by A as the sole route-removal mechanism. It does
  not attempt to restore link-down or
  EUI-64 state and does not run ordinary per-address rollback after the first possibly-sent link
  mutation. Both route owners, all four address owners, and both pair owners remain armed. After
  deleting both pairs, PID 1
  restores the exact retained original `ip_forward` record while the structural generation-2
  policy remains under counter-agnostic cleanup authority: an original `0\n` causes one bounded
  two-byte restore write, while an original `1\n`
  requires no write. The retained parent and endpoint baselines then prove all three namespaces
  byte-exactly equal to the enumerated network baselines for that restored phase while the exact
  generation-2 policy structure remains active. PID 1 then deletes only the freshly
  observed table handle in one generation-pinned atomic transaction, proves a semantically empty
  generation 3, and binds the final RTNL/proc and endpoint reproofs to that result. Only after those
  final proofs does one prevalidated infallible retirement barrier disarm the route, address, and
  pair owners. The restoration claim covers only the fixed `ip_forward` record: Linux may reset
  related per-device IPv4 configuration when forwarding changes, those additional devconf values
  are not exhaustively enumerated here, and their complete removal relies on destruction of the
  disposable parent network namespace after its last reference closes; this slice does not
  separately observe that destruction. PID 1 then ensures every detached-clone and transient
  visible-pin
  descriptor is closed before ordinarily unmounting nsfs B and then A with `UMOUNT_NOFOLLOW`,
  proves the hidden empty slots and exact original mountinfo baseline are restored, and removes
  every owned mount and link plus every transaction-retained descriptor reference. Namespace
  destruction after the last reference closes is governed by the kernel's reference-counting
  semantics and is not claimed as a separately observed event. The transition then rolls back slot
  B, slot A, the per-run directory, the workspace root, and the netns root, with the required
  directory `fsync` barriers. PID 1 returns to the `PristineRun` state, revalidates the pinned
  network baseline and private mounts, and emits the internal, canonical
  `MUTATION_ROLLBACK_COMPLETE` record through the launcher. The outer
  accepts and run/PID-binds that checkpoint, then independently proves that the private `/run` is
  empty again before sending exact TERM through the PID-1 pidfd. PID 1 consumes the real `signalfd`
  record and returns an affine run/PID/signal observation through the launcher. Lifecycle EOF is
  necessarily
  post-`GO` and is classified as `CleanupRequired`, after which PID 1 is exactly reaped.
  If the outer PID-1 pin is unavailable after spawn, one run-bound pre-mount abort record
  retires PID 1 without issuing a mount instruction. Only `EPERM` or `EACCES` from a fixed
  mount-UAPI operation may produce the exclusive
  `BlockedAtPrivateMountSetup` policy result; all malformed state, unsupported APIs, invalid
  options, resource failures, and failed evidence remain hard errors. The positive
  `BlockedAfterFixedIcmpEchoTeardown` route proves that complete read-only network baseline,
  one real pinned `BOOTSTRAP_READY`, the canonical `GO`, affine authorization consumption, the
  descriptor-relative root/slot transaction, two live pristine nsfs pins, two fixed down-veth
  pairs each created through one atomic `RTM_NEWLINK` request, their exact parent/A/B delta proof,
  the four fixed `/30` IPv4 addresses and exactly four kernel-created local-table `/32` routes while
  all ends remain down, the separate all-addrgen-NONE barrier, atomic exact generation-2 parent
  FORWARD policy installation, exact carrier-up activation of all four ends with `noqueue` and the
  complete kernel-created route set, both exact static endpoint routes and their exact parent/A/B
  observation, exactly four semantically proved permanent neighbours with zero probes and zero
  proxy-neighbour records, one no-retry 40-byte raw ICMPv4 request from endpoint A, one exact
  60-byte reply bound to the full canonical run ID, two identical post-close policy-counter
  observations at request/reply/drop `1/60`, `1/60`, `0/0`, and exact one-RX/one-TX plus 74-byte
  RX/TX telemetry on every veth end. It further proves canonical reverse neighbour removal back to
  the exact routed state without changing that telemetry, a final exact counter-profile reproof,
  conversion to counter-agnostic policy cleanup authority, direct veth B/A deletion, complete pristine reverse
  proof under generation 2 after exact restoration of the original parent `ip_forward` record,
  handle-only policy deletion, semantic-empty generation 3, final
  parent/endpoint reproof before route/address/pair owner retirement, the
  internal rollback checkpoint,
  the post-rollback empty-`/run` proof, the TERM/EOF/signal chain, and exact PID-1 exit/reap. The only
  transient topology is the two otherwise-pristine network namespace objects, their kernel-default
  loopback/rules, their nsfs mounts, two fixed veth pairs, four fixed IPv4 addresses, four active
  link ends, four `noqueue` qdiscs, fourteen associated IPv4 routes, four IPv6 multicast routes,
  four affine `NUD_PERMANENT` IPv4 neighbours, and the one transient exact `inet`
  policy table/chain/three-rule counted set. The parent namespace's fixed
  `ip_forward` record is conditionally changed from `0\n` to `1\n` and restored to `0\n`; an
  inherited `1\n` takes the no-write path throughout. The outer host record remains byte-identical.
  This slice proves one fixed run-bound ICMPv4 echo exchange and its joined reply/counter/link
  evidence. It makes no packet-absence, packet-capture-privacy, general VPN datapath,
  network-topology-readiness, `TOPOLOGY_READY`, forced-crash-cleanup, A14, A15, or acceptance claim.
  Repeated portable tests prove exact
  outer-launcher reaping, unchanged outer namespace/mount observations, and an unchanged canonical
  outer fingerprint of stable link fields,
  addresses without expiring lifetimes, IPv4/IPv6 routes and policy rules, nexthops, qdiscs without
  counters, IPv4 `ip_forward`, IPv6 `all/default` forwarding, and `/etc/resolv.conf` object/target
  identity plus content. They
  exclude volatile neighbour/carrier telemetry and do not claim an authoritative comparison of host
  nftables/legacy-firewall state, resolver-daemon caches, or VPN-private peer/key state. This remains
  rollback evidence rather than A14, A15, or acceptance evidence.
  Normal reaping retains both pidfd and exact `Child` ownership; every forced `SIGKILL` after
  admission targets that pidfd.
  Pidfd acquisition is mandatory; its failure closes the private channels, attempts `SIGKILL`
  against the still-owned unreaped child, and synchronously waits/reaps it before returning the
  pidfd error. The public `--run` entry requires one task, and a non-default `SIGCHLD` handler or
  `SA_NOCLDWAIT` is rejected before any spawn. The rare process-local fallback-reaper path is not
  post-exit cleanup or A14 evidence. Required parent, namespace, mapping, mount-policy, and outer
  PID-1 proofs fail closed when kernel policy hides them. Generic CI may therefore prove only
  fail-closed behaviour. Pre-isolation parent-proof or namespace-policy denial uses a bounded
  control/lifecycle half-close handshake that keeps the launcher alive until the outer
  acknowledges EOF, preventing an early-`SIGCHLD` race; only the outer containment deadline bounds
  that wait. Complete live evidence for this slice requires the explicit
  `BlockedAfterFixedIcmpEchoTeardown` outcome. At supervised IPC boundaries, managed outer
  HUP/INT/TERM prioritizes bounded exact-launcher containment; the live gate does not yet prove
  external-signal handling across every reap/report phase, general descendant reaping, forced
  parent-death/crash-chain cleanup, or A14. The production ownership and namespace modules and their
  affine `PristineRun`/`AuthorizedPrivateRun`/`AuthorizedNamespacePins`/`AuthorizedVethPairs` and
  borrowed `AuthorizedIpv4Addresses`, `AuthorizedIpv4AddrgenNone`,
  `AuthorizedActivatedTopology`, `AuthorizedEndpointRoutes`, `AuthorizedPermanentNeighbours`, and
  `AuthorizedDeletedTopology`
  typestates plus the affine initial/active/retired nftables authorities, the enabled/restored/
  indeterminate IPv4-forwarding authorities, and
  `PolicyBoundPrivateMounts` are active in the runtime path for the
  descriptor-relative private-root, empty-slot,
  two-pin, two-veth, four-address, counted forward-policy, conditional parent-forwarding enable/restore,
  link-activation, endpoint-route, permanent-neighbour, fixed-ICMP echo, deletion-only link teardown,
  and exact policy-retirement
  transaction described above. A provisional
  containment guard is installed immediately after each exclusive creation. Within this fixed
  runner's one-PID-1-task and trusted-launcher scope, an inotify witness rejects delete, move, or
  recreate activity during the non-atomic `mkdirat`-to-open handoff. A retained descriptor plus
  that exact handoff observation permits only a scoped cleanup attempt; the guard performs an
  immediate second descriptor/path/parent/shape revalidation before any unlink. If the new
  directory cannot be pinned unambiguously, it is not unlinked by name and the
  run fails closed until its disposable mount namespace is torn down. Only fully pinned and
  journalled entries can reach the rollback-complete checkpoint. This is not an identity-conditioned
  kernel unlink primitive and does not defend against a hostile mapped-same-UID process that
  already holds a writable descriptor into the private mount. A production helper must establish
  root-owned exclusive mutation authority before reusing this transaction. A private
  `cfg(test)`-only Rust model still covers the separate canonical ownership manifest
  reader/classifier and atomic tempfile publication machine. It verifies exclusive
  pending creation, exact bounded readback, file/directory sync, no-replace rename, immediate
  pinning, failpoints, and reverse identity-scoped unlink of its own synthetic regular-file
  fixtures. Manifest publication remains test-only: production does not create or publish an
  ownership manifest. The runtime does construct and fully reverse two transient live nsfs pins,
  two fixed veth pairs, four fixed IPv4 addresses, four active link ends, two explicit endpoint
  routes, four explicitly removed permanent neighbours, the exact kernel-created qdisc and route
  side effects, one fixed run-bound ICMPv4 exchange with exact reply/counter/link evidence, and the
  transient generation-2 nftables policy's affine zero-to-`1/60,1/60,0/0`-to-cleanup transition
  described above, but proves direct link deletion, handle-only policy
  retirement, and
  ordinary unmount only within its fixed one-PID-1-task and
  trusted-launcher scope.
  Cleanup uses the retained parent directory through a descriptor-rooted
  `/proc/thread-self/fd/<fd>/<leaf>` path, with an identity verification before ordinary unmount;
  the intervening path lookup means this is not a race-free unmount proof against an excluded
  hostile mapped-same-UID actor. A production helper must provide root-owned exclusive mutation
  authority before reusing it. The link-activation, exact endpoint-route, exact permanent-neighbour,
  exact nftables-policy,
  fixed ICMP socket path, and fixed parent-namespace `ip_forward` writer are fixed and bounded; no
  general sysctl, general nftables, ownership-manifest, packet/probe, or general route/neighbour
  mutation API exists. The only route objects
  admitted in this slice are the exact kernel-created local,
  connected, high-broadcast, and IPv6 multicast routes coupled to the fixed address and activation
  transaction plus the two exact static `/32` endpoint routes described above. The only ordinary
  neighbour objects admitted are the four exact affine `NUD_PERMANENT` IPv4 records described
  above; proxy neighbours remain forbidden. The slice
  still has no general
  root-filesystem or supplementary-group isolation,
  `TOPOLOGY_READY`, `STOP`, `FINISHED`, configured dataplane-topology mutation, crash-cleanup evidence,
  acceptance report, or A01-A15 result. In particular, the deletion-only fixed-link teardown is
  not forced-crash cleanup or A14, A15, or acceptance evidence. `BOOTSTRAP_READY` remains
  readiness evidence; `GO` authorizes only this bounded private-root, two-pin, two-veth,
  four-address, counted forward-policy, conditional forwarding enable/restore, link-activation,
  endpoint-route, permanent-neighbour, fixed-ICMP, and policy-teardown transaction,
  and `MUTATION_ROLLBACK_COMPLETE` is an
  internal containment checkpoint rather than cleanup or acceptance evidence.
- [ ] Integration run performs real discovery, advertisement, selection, reservation, WireGuard, MPTCP, MPQUIC, TCP, UDP, and HTTP/3 operations.
- [x] Machine-readable acceptance report is emitted.
  `tests/integration/run.sh --execute --suite all` now builds unchanged product binaries and enters
  anonymous user, mount, PID, and network namespaces before making any network change. It creates
  a Client, two non-adjacent Relays, an Exit, and a destination topology, launches four real
  `volparossa-agent` processes plus TCP and UDP destination endpoints, and uses a short-lived empty
  three-signature development policy so policy provisioning does not hide the next product gap.
  The real client `connect` request currently fails closed at `DATAPLANE_UNAVAILABLE`; this is the
  first observed product blocker, and no datapath case is claimed. Normal teardown stops every
  process and reports zero remaining owned namespace objects. On the exercised Debian 13 host,
  links, addresses, routes, rules, DNS and IPv4 forwarding matched before and after. Because that
  host has no `nft` observer, full firewall-state evidence and therefore A15 remain explicitly
  skipped. The fixed alpha score remains **11/100 (11%)**.

### Required acceptance tests

- [ ] A01 discovery survives loss of either bootstrap peer.
- [ ] A02 TCP download proves at least two data-carrying MPTCP subflows.
- [ ] A03 constrained MPTCP paths aggregate bandwidth beyond one path.
- [ ] A04 removing a relay does not terminate an active MPTCP download.
- [ ] A05 UDP echo uses exactly one relay and no direct client-exit datapath.
- [ ] A06 HTTP/3 through MASQUE proves at least two data-carrying MPQUIC paths.
- [ ] A07 removing one MPQUIC relay avoids unnecessary inner-QUIC interruption.
- [ ] A08 allowed test domain succeeds.
- [ ] A09 domain, raw-IP, SNI, and forbidden-port policy denials succeed.
- [ ] A10 unverifiable ECH fails closed.
- [ ] A11 relay capture reveals no Internet destination in the routed outer layer.
- [ ] A12 exit capture sees relay peers rather than the client's public address.
- [ ] A13 client capture proves there is no direct client-exit dataplane route.
- [ ] A14 forced crash plus cleanup removes all temporary network state.
- [ ] A15 original host routes, DNS, firewall, links, sysctls, and VPN state remain unchanged.

## Performance and packaging

- [ ] Benchmarks cover one/four relays, TCP/MPTCP, QUIC/MPQUIC, RTT spread, loss, jitter, capacity, CPU, memory, context switches, WireGuard overhead, setup, discovery, and failover.
- [ ] Reports distinguish net user data from physical tunnel data.
- [ ] The Debian 13 bootstrap script previews packages, asks permission, and performs no direct
  route/DNS/firewall/VPN mutation; package-maintainer service side effects are not independently
  constrained or audited.
- [x] System-check script is read-only.
- [ ] Reproducible `.deb`, hardened systemd units, tmpfiles, users/groups, optional logrotate, uninstall, and cleanup instructions are provided.

## Documentation

- [ ] README accurately covers purpose/non-goals, architecture, install, demo, roles, warnings, limitations, and threat-model link.
- [ ] Architecture document contains discovery, reservation, WireGuard, MPTCP, UDP, MPQUIC, cleanup, and policy diagrams.
- [ ] Protocol document specifies every wire message, limits, canonical form, signatures, and versioning.
- [ ] Threat model covers every required adversary/attack and clearly states global-observer limitations.
- [ ] Discovery, routing, MPTCP, MPQUIC, whitelist, operations, testing, and privacy documents match implemented behaviour.

## Definition of done

- [ ] Every master-specification completion criterion is evidenced above; all checks and linters pass; packaging and the complete real-network acceptance suite pass on clean Debian 13.
