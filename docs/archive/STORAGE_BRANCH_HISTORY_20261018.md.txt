# Retained Storage branch evidence — 18 October 2026

This is a verbatim historical ledger excerpt from retained source
`b02f3333d1908aeb14f39134fccd58be7e8391a6`. Its last-update date was
18 October 2026; subsequent merge commits preserved that ledger unchanged.
Past references to current work, pending checks or open PRs describe that
snapshot. Use [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for the
current plan and outcomes. Original failures, uncertainty and source bindings
remain historical evidence and are not superseded by later passing trials.

The excerpt runs from “Latest storage consumer outcome” through the section
before “Explicit local policy for protected compute”. Its exact payload is
206519 bytes, SHA-256
`26344b98b81fb4554f6c76becefb58046d0cc086a0f7baf5865a9162728b63ff`. The full original ledger remains
[available at its immutable source](https://github.com/VOLPAROSSA/volparossa/blob/b02f3333d1908aeb14f39134fccd58be7e8391a6/docs/IMPLEMENTATION_STATUS.md).

<!-- BEGIN HISTORICAL LEDGER EXCERPT -->
### Latest storage consumer outcome

Original source run
[`38915098088`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38915098088)
passes on `acba3244`: 147 Rust tests, including two isolated kernel cases,
296 Python tests, 50 Node tests and 48 normalizer checks, with compilation,
strict lint, formatting, exact source and host-state checks. Subsequent original
actual run
[`38917106698`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38917106698)
fails Cloud publication at RESERVE fragment 0/copy 1: provider TLS reaches its
handshake deadline. Consumer maintenance, repeated restoration, deletion and
remote cleanup remain unproven. Owned topology cleanup and unchanged guest-root
network state pass; those do not prove remote consumer-data cleanup.

The bounded correlation record matches a client and provider-B connection whose
two TLS handshakes both time out. Matching covers the first 64 ClientHello bytes,
not complete delivery or the return handshake flight. The collection is
incomplete and has no fragment/copy binding, so it cannot establish that this
connection is the failing copy or identify the cause. Original artifact/log CRC
checks and the API artifact digest pass; their ZIP SHA-256 values are
`90711701e55a011b362058ee1577ccd8b276131cae15aa977d4b5c7842a72340`
and `1f28e0f3e71f29d29fad1d1ab6f4d30344117fbeeec1c22618dbfb329ba17cec`.

### Repeated storage reservations through production egress

The targeted regression covers a gap in the earlier TLS-close tests, which
preconnect the provider socket and bypass production SNI inspection, DNS,
connection setup and ClientHello replay. It performs three distinct signed
RESERVE exchanges through `ExitService::run_tcp_egress`, reusing the verified
route, listeners and provider store. Each connection negotiates genuine kernel
MPTCP and nested TLS; partial reads and bounded writes exercise the real proxy.
Success requires three verified distinct reservation receipts, completed closes,
joined tasks and no surviving owned socket descriptors.

A synthetic DNS-over-TCP fixture supplies the exact permitted hostname through
the existing fallback path with caching disabled. Its provider address is added
only to loopback inside the explicitly checked disposable namespace before
privileges are dropped; no host route or production egress permission changes.
This is not a DNSSEC/Unbound implementation test, activated route admission,
deployed WireGuard relays or proof of multiple live subflows. Production
handshake/setup deadlines and privacy controls remain unchanged.

Original hosted source run
[`39073538705`](https://github.com/VOLPAROSSA/volparossa/actions/runs/39073538705)
on `40348fe5ce6b8ed2172b2e6b7bfb848de677d07c`, tree
`4b446c82863c7ef86189b4fd6a04639ed304b1ef`, compiles and passes strict lint,
148 unique Rust tests, 296 Python tests, 50 Node tests and 48 normalizer checks.
All three exact kernel cases pass; the new production-egress case takes 1.86
seconds. All 62 source bindings, 21 unchanged dependency blobs, the separately
pinned namespace runner and final source/host-state comparisons pass.

The workflow fails only one formatter hunk in the new test. The follow-up applies
that exact whitespace change; unchanged-source acceptance of the correction is
still required. Original artifact/log CRC checks and the API artifact digest
pass, with ZIP SHA-256 values
`53e344421ca48090fd9e1b50f17d8b7f55c387fe9321d16effd88067f6ae9d9c`
and `8f65b0f54204a497ea4c94eece4217249d47b1c6ee2506c60865a15ff1891ee5`.
These passing exchanges do not establish the original consumer timeout's cause
or replace complete Image/Cloud maintenance acceptance. Activated reusable routes,
real relay subflows and daemon lifetime handling remain outside this regression;
the dependent upload lifecycle stays deferred.

### Earlier storage consumer outcome

Source run
[`38898873084`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38898873084)
passes on `2ce38aa9e336f48f11f21d9ffdd7c95ddc9083fb`: 47 unique Rust tests
(21 existing contracts, 24 TLS-v9 cases and two explicitly executed kernel cases),
290 Python tests, 50 Node tests and 48 firewall-normalizer checks. Compilation,
strict lint, formatting, final source and host-state comparisons pass. Original
source artifact and log ZIP SHA-256 values are
`bf2c850bee6b5cfac785b3407e3081486b6a2cf63c8ffe59959f731c5770f27f`
and `db24795af5be0c8d27560681ca0b28a8b3f61fa2b71bb469f3c450f1a16004ee`.

Actual run
[`38900639690`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38900639690)
uses that exact source, tree `52630940c62af032612c8ae97158cfa1b9080565`,
consumer profile 10 and the unchanged Image `1e812ec6` / Cloud `35598609` pins.
The separate core lifecycle passes loss/resume, two hash-verified non-consuming
restores, three verified replacements, deletion of all eleven retained copies
and the foreground copy, and zero final usage at all three base providers.

The combined consumer gate fails Cloud FINALIZE, fragment 0/copy 0, at
`stream_open / flow_acquire`. Two acquisition rounds report `helper_kernel`
then `helper_cleanup_incomplete`; there is no TLS-close outcome for this failure.
The separate helper sidecar contains one `poll / timed_out` observation without
an errno. It is not request-bound and cannot establish this failure's cause.
Image publication precedes Cloud by the tested source's control flow, but no
separate completed Image receipt was exported. Consumer repair, restoration and
final deletion are not reached; remote consumer cleanup and usage remain unknown.

Local consumer cleanup, guest cleanup with zero owned objects, normalized
guest-root network-state equality and normal QEMU stop/join pass. There is no
independent scratch-removal receipt. The conditional double Debian-package build
is skipped, not passed. Both original ZIP CRC checks and the artifact API digest
pass; artifact and log SHA-256 values are
`2c07ad288397cbd1e8b275d809cd79ffa4c5b62cb6cf1aaacdba72219c73ab0b`
and `1b08929555cfb09bdcf08affd0330c81610aa4fc384ef3d675103be36ae9cd0e`.

### Request-bound helper diagnostics in the development fixture

The next candidate retains a closed helper rejection category after checking
the helper's credentials, request identifier and operation digest. It records
the original first/last acquisition failures and round count in fixture schema
2. Missing authenticated detail remains absent; an authenticated but unrecognized
token becomes `unknown`, never raw text. The two expired-cleanup categories refer
to the helper's global reap boundary, not proof that this request's route expired.

Only a client acquisition ending in an operation error can expose that summary.
Stage changes, cancellation and non-error completion invalidate it, including
when a contended observation lock prevents clearing the retained record. The
existing caller-owned epoch binds the selected fixture version. Version-1 wire
and JSON, production diagnostics 7–9, helper results, deadlines, retry limits,
route retirement, descriptor ownership and application pins remain unchanged.

This fixture-only detail is request-local, not a TLS fingerprint or a binding to
a provider, fragment or copy. It does not establish a cause or remote cleanup.
The bounded sampler keeps the existing query and record limits; no extra helper
operation or network probe is added. Hosted compilation, lint and targeted
contracts must pass before another full consumer trial. Image/Cloud maintenance
and the dependent upload-to-repair-to-restore trial remain incomplete.

The local inert checks pass 296 Python tests and 50 Node tests, including the
33 sampler cases and existing maintenance exporters. Independent source review
passes. Original hosted source run
[`38913088623`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38913088623)
on `4e2e6a760598009dadb3c9ab5d8bc76722888d68` compiles and passes all 147
distinct Rust cases: 17 new fixture cases, 128 existing contracts and two isolated
kernel tests. It also passes 296 Python, 50 Node and 48 normalizer checks, all
source/dependency bindings, and unchanged final source and host-state comparisons.
It fails only strict lint on one `nonminimal_bool` condition and six formatter
hunks. The follow-up applies those exact formatting changes and the equivalent
`is_none_or` predicate; it still needs unchanged-source acceptance before an
actual consumer trial. Original artifact and log ZIP SHA-256 values are
`b8459641f3f2167f56694b1b62d34141c9ec18d5555e3c0c2114bfd37491f170`
and `e862446781fc60475a8c1315ddc3b4ea778bd2f1fa299549116906c94ceff5eb`.
These contracts do not establish a fix for the consumer runtime failure.

### Earlier storage TLS close outcome

Original actual run
[`38884826395`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38884826395)
fails on exact `33faa7449ee982f8114c001107692eedf03cb5d5`, tree
`2bfdb093e2783bad00419c22ede27edeef5fd9a0`. The base storage lifecycle passes:
eight uploaded copies, repair after provider withdrawal, two restores, deletion
of all eleven copies and zero remaining usage at all three base providers.
The strict base evidence and real two-path MPTCP/privacy checks pass. Those
results do not accept the separate application-consumer lifecycle.

Cloud RESERVE fragment 0/copy 0 fails at `agent_terminal`, with outcome phase
`transport_tls_close`, category `unavailable` and no enclosing deadline expiry.
The source reaches that phase only after the admitted bridge and inner provider
TLS closure succeed. The outer TLS close function combines shutdown, read,
trailing-byte and its own timeout failures; the specific cause is not yet known.
Final route/grant/lifetime validation and `CONTENT_OK` are not reached. This is
not the earlier handshake failure, and does not prove that its cause is fixed.
The helper bind observation and matched fixture-closing records are not bound
to this exact copy and cannot establish its cause.

Guest cleanup reports zero owned objects and unchanged host network state;
QEMU stop/join and local fixture cleanup are supported by the original run.
Remote consumer cleanup and usage remain unproved, as do complete Image/Cloud
repair and restoration. Original application pins remain unchanged: Image
`9694a2b9` and Cloud `47b0f03b`; all 23 provisioned app blobs match. The workflow,
consumer profiles and acceptance validators also match the previous trial.
Original artifact API digest and both ZIP CRCs pass; artifact and log SHA-256 are
`537c75bd4de2f3239073633671d96023394569ece23921a20b202d91f24ef759`
and `c999e511e28b15437007ff7e883bb427e2bdb5d3ab6c0c9c83f43b9f147607c0`.
The next step is to distinguish and reproduce the outer TLS close failure before
another actual consumer run; do not extend deadlines or accept abrupt EOF.

### Isolated kernel test for nested TLS closure

Two new test-only cases exercise a signed RESERVE through negotiated loopback
kernel MPTCP, the production bidirectional proxy and a real TCP storage provider.
The normal case closes and drops the provider, then joins and drops the proxy
before the client explicitly finishes its outer TLS stream. The negative case
aborts the proxy before its outer close notification and must reject an actual
EOF/reset, not merely expire a test timer. Both retain one ten-second scenario
deadline and join owned tasks before checking that all four sockets are gone.

Original hosted run
[`38893288966`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38893288966)
on `fd4ba6a3cfb81c1ac28ab1c349fe532e8ac2f291` compiles the agent and passes strict
lint, the 21 existing contracts and both explicitly selected kernel cases, with
none failed or ignored. The normal case completes in 0.78 seconds and the abrupt
negative control in 0.77 seconds. Both run in disposable network/PID namespaces;
host route, DNS and normalized firewall snapshots are identical. All seven source
blobs, twelve unchanged dependencies and the isolation runner match. The 48
firewall-normalizer cases and final source-preservation check also pass.

The run fails only one formatter hunk. The follow-up applies that exact layout
change without changing behavior. Original artifact and log ZIP SHA-256 are
`e35f38c2403a64415f0c5330302df29739e98ac76c0477c1c476985a418e4939`
and `0771c2d8d8aabcc91cb7b0ab4a87be7a54c1769c29924cbdde0bc0fb5d1e4a4a`;
the artifact API digest and both ZIP CRC checks pass.

These scoped results do not reproduce the consumer failure or prove a deployed
WireGuard/multipath route. Production closure behavior, deadlines and consumer
validation remain unchanged. Next, preserve the actual outer-close failure class
in the existing caller-bound diagnostic, without exposing payloads or changing
success criteria, before another full Image/Cloud trial.

The next source candidate implements that opt-in diagnostic end to end. Version
9 retains every version-8 field and adds one nullable, closed outer-close reason:
`shutdown_io`, `read_io`, `trailing_data` or `internal_deadline`. It is tied to the
same caller/request/fragment/copy and existing one-use outcome query, not inferred
from another flow or raw logs. Older encodings and selectors remain unchanged.
The production close sequence, ten-second internal budget, three-query/one-second
observation limit and transfer success criteria are preserved. An I/O timeout
is not relabeled as expiry of the internal TLS budget. No payload, URL, raw error
or private operation identifier is exported.

Consumer profile 10 pins Image `1e812ec6424a539a336d230b99ae1c11a494ca29` and
Cloud `35598609d3fedb5d1241a479c1930c8a6b831661`. Its 23 source files include the
same byte-identical shared adapter and explicit provenance; historical profiles
1–9 and the Node runtime stay unchanged. Both applications' actual script/config
paths are tested with an inert child; 117 targeted application tests pass.
The core's 290 Python and 50 Node harness tests pass, including strict profile
binding, failure preservation and the original network/custody/cleanup gates.
Original hosted run
[`38896943885`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38896943885)
on exact `7cf5f3e489e9d82cf32e26341487344501d4baff`, tree
`4d5538de8c51b21cd72ede189e8021e71fb6ac12`, compiles all three affected packages
and passes the 21 existing Rust contracts, 24 new diagnostics contracts and both
explicitly selected kernel cases. The 290 Python and 50 Node harness tests also
pass, with no failures or skips. The 48 firewall-normalizer cases, unchanged
host network snapshots and final source-preservation check pass.

The overall run fails strict lint on three large futures in the new CLI tests
and seven formatter hunks in five files. The follow-up boxes only those test
futures and applies the reported layout changes, preserving assertions, timers
and production behavior. No lint is suppressed. The revised source still needs
hosted acceptance before the full consumer trial. Original artifact and log ZIP
SHA-256 values are
`b857c35061f74d077c058bf933955a139f09e26c418590e52fc309d0afe0b9c6`
and `eb0c4c8ae7a8347aaf187dba2a410ce51b0ec8e1daa206f382a4176e29c5f4d8`.
These scoped checks neither accept Image/Cloud network maintenance nor explain
the earlier consumer failure.

### Fresh TCP admission after route-slot waits

The preceding actual consumer trial
[`38860289559`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38860289559)
on `08ba6b21b79bef8fb0f124f114fb5ba3df7d93b7` still fails Cloud publication.
The first copy fails during the provider TLS handshake; the next fails flow
acquisition with `helper_cleanup_incomplete`. Base restart, repair, two restores
and deletion pass, with all three base providers returning to zero usage.
Complete Image/Cloud consumer maintenance and remote consumer cleanup remain
unproved. Guest/local cleanup, QEMU shutdown and host-state checks pass.
The bounded observations do not bind the timeout to an exact Cloud operation or
prove a shared cause for both failures. `helper_cleanup_incomplete` can also
represent a stale operation whose rollback succeeded; it does not by itself
prove that resources remain allocated.

Source inspection identified a separate admission gap: TCP flow acquisition
sampled expiry before awaiting the route-state lock. Lock waiting or an existing
acquisition attempt could cross the original deadline before the next helper
call. The candidate now samples wall and monotonic clocks after taking that
lock and before each subsequent attempt. Expired routes enter retained
retirement under the same lock; cancellation cannot discard their cleanup
owner. Material validation uses the freshly sampled time.

Eight new contracts cover live admission, expiry during lock waiting, monotonic
expiry despite wall-clock rollback, expiry between attempts, cancellation,
failed cleanup, an existing retirement and production callsite binding. They use
inert affine-owner fixtures, not a substitute MPTCP datapath. The original
eight-attempt limit, helper budgets, route lifetimes and storage-consumer pins
are unchanged. This correction is not yet proof that the original TLS timeout
or complete consumer lifecycle is fixed.

Original source run
[`38882687116`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38882687116)
on exact `6c817ccc6dcc2130fc3df823fea23948dba032c7` passes compilation,
21 unique Rust cases (eight admission, seven retirement and six historical),
strict lint and source preservation, with none failed or ignored. Five source
blobs and twelve unchanged dependencies match. The overall run fails only six
formatter hunks in two files. The follow-up applies those exact hunks, with no
behavioral change. No local Rust execution is claimed. Original artifact and log
ZIP SHA-256 values are
`b36a814b451cc69b8dc83c4653cad4ba25db6ca240e610a752964500e75b5cee`
and `5c10d94b54b0991883e588ece4960a00d2213992227e3b766ce88c3dc2e688e7`.

Corrected source run
[`38883801795`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38883801795)
on `33faa744` passes compilation, all 21 contracts, strict lint, formatting and
final source preservation. Five changed blobs and twelve dependency identities
are verified. Artifact and log SHA-256 are
`b5e7d1fce35d45d24a4027fb87bc599f5816243e78ce5f932031281bf955fcb9`
and `c7752a29d12860ae102e0e3600e26f0428f025b15525887c4ef910d5ea0ab482`.

### Retained route retirement after helper loss

Source inspection following actual `38851643524` found a separate cleanup race.
When MPTCP acquisition loses helper-route ownership, the controller publishes
`Idle` before awaiting route shutdown. Another request can therefore see an
available controller before cleanup finishes, and cancellation can drop the
caller-owned shutdown future. That path also discards the shutdown result.
This contradicts the retained `CleanupPending` contract already used by explicit
disconnect and signed route expiry; it does not prove why the original connection
poll timed out.

The correction keeps the exact retiring route in `CleanupPending` before
unlocking admission. It reuses the existing retained cleanup task and bounded
confirmation, so caller cancellation cannot acknowledge or cancel retirement.
Only confirmed cleanup of that same owner may publish `Idle`; failure remains
pending. The original flow-acquisition failure and its diagnostic history remain
the caller's result. No route lifetime, retry count, helper timeout, consumer pin
or storage-operation replay policy changes.

Six behavioral regressions target that failure branch, concurrent admission,
caller cancellation, quarantine recovery, terminal cleanup failure and delayed
completion against a different owner. A seventh test guards the production
callsite. Independent source review and local workflow syntax/diff checks pass;
Rust has not been executed locally. The dedicated hosted source gate compiles
and tests the affected agent, runs six existing disconnect/expiry/classification
contracts alongside those seven new cases, and checks strict lint, formatting
and exact source bindings. Original hosted run
[`38858477859`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38858477859)
on exact `392ace51bd589258a708f483532c9872b5378550` passes compilation,
all 13 unique Rust cases, strict Clippy and source preservation, with no failed
or ignored tests. Four source blobs and twelve unchanged dependencies match.
The run remains failed solely because seven layouts in the new test file do not
match the formatter. The correction applies those exact layouts only; production
bytes and test behavior are unchanged. The corrected original hosted run
[`38859556567`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38859556567)
passes on exact `08ba6b21b79bef8fb0f124f114fb5ba3df7d93b7`: compilation, all
13 unique Rust cases, strict lint, formatting and source preservation. Four
source blobs and twelve unchanged dependencies match. Its original artifact
and log ZIP SHA-256 values are
`4d3fa36c1ce643aa8eec8c89525e440fb6ca5282239cdd7d776f1d450073bfe0`
and `2a07541089aa680bf1b1822a9a22585872c7cf8d53950f19ea40642171784521`.
For the earlier failed `38858477859`, original artifact and log ZIP SHA-256 values are
`b927a7621d4dbba497d1dbed28780f73b651b780ee73b908f8b7c04d2a22921a`
and `078d19281d6002efeb515a7f6de36c9f6a9a025b7cbb29b30060a05c7c4e3517`.
These are targeted controller contracts, not a full distributed datapath trial.
The near-expiry route-selection hypothesis remains unresolved.
Complete Image/Cloud publication, maintenance and remote cleanup must still pass
the actual consumer trial after the source correction is verified.

### Closed helper acquisition diagnostic candidate

Actual run
[`38838512301`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38838512301)
on `9209c6feced0db5da5cae614775769c60b2ff11b` reaches Cloud publication but fails
APPEND fragment 0/copy 1 before TLS: the first flow-acquisition error is
`helper_kernel`, the last `helper_cleanup_incomplete`. Its valid correlation
sidecar does not identify the kernel operation or bind that event to a fragment.
The base lifecycle, restore and delete checks pass, but consumer maintenance and
remote cleanup remain unproven. The earlier Image challenge stall in
`38816407455` is a separate unresolved failure. Original artifact and log ZIP
SHA-256 values for `38838512301` are
`533cdd4463ae281c4e11ffeb3d32c7dc65ee6432b80629184295e04deb71490c`
and `400c49417576e1c455bced674b73b37e7df6b8033f607c18dc00d55636843eef`.

The next source candidate preserves the socket operation, closed failure class
and optional original errno inside the helper's credentialed response. This
optional detail applies only to a failed client MPTCP acquisition; it contains
no address, path, peer identity or free-form error. It does not change the public
helper response, original result, deadlines, retries or descriptor cleanup.
Existing responses without the detail retain their bytes. A later parent-side
descriptor-adoption failure may still report `Kernel` without this detail.

The fixture projects the private client-helper log after the existing helper
shutdown into `private-storage-maintenance-helper-acquire.json`. It reads at
most 4 MiB, retains at most 64 closed records and exports at most 16 KiB. Missing,
changed, malformed or truncated observations stay explicit. Normal and emergency
export validate the same schema; raw helper logs remain excluded. This projection
does not bind a record to an application request or fragment/copy, prove the
cause, prove absence of other failures, or establish remote cleanup. Diagnostic
failure cannot replace the original consumer result.

Thirteen new Rust contracts cover the closed response, credentials, descriptor
rejection, unchanged result mapping and typed tracing. The source workflow
compiles the helper and its real entrypoint, runs those and selected existing
boundary contracts, and checks the Python projection and maintenance exporters.
Original hosted source run
[`38846990417`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38846990417)
on `d252cd25cb3abfe9dbdd91f551240e0ffd0b51f5` compiles both packages and passes
33 unique Rust cases (13 new, 20 historical) and 168 Python cases, without failed
or skipped tests. The overall run fails three strict-lint findings and formatting;
it is not a passing source gate. Original artifact and log ZIP SHA-256 values are
`2fd3f05b512fb5a893708f62683a7b13edfbc43a3958a528b18a0769bbf3ae42`
and `77004ac080d65b3c45d865ac95291f15a522619ccfd14a905d027df6ed3d25e1`.
All 16 source blobs and 11 unchanged dependencies match the original manifest.
The narrow correction passes compilation, the same 33 Rust and 168 Python cases,
and strict lint in original hosted run
[`38848309510`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38848309510)
on `85de72d41a9eb9350179c65aefd00dcf66909a0d`. One test-call layout still fails
formatting, so this run also remains failed. Its original artifact and log ZIP
SHA-256 values are `02633bc99253ea96af875a96a51308807e6921a3c973c25366ed8fdd344ad146`
and `1d2d3c0cfa534ce491f318fc1cda96950ea59742b7f4db8e9513aa2ddb3fb37b`;
all source and dependency blobs match. The exact formatter correction passes
original hosted source run
[`38849123582`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38849123582)
on `04f51e5cd7f17d736979872e4e64968d79d0540f`: compilation, the same 33 Rust
and 168 Python cases, strict lint and formatting. Its original artifact and log
ZIP SHA-256 values are
`6213fe56d8978d5d3cd04990bf45194af7be94c1c1a2fc3828f7d2de0f149e1e`
and `e9e3385c7e8c38fd6f457422abe3218b026fad9e16f18dacf78289e54b0c6c06`;
all 16 source and 11 dependency blobs match.

Actual run
[`38849945061`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38849945061)
on that exact source fails its inert preflight before VM preparation. Three
sampler test methods incorrectly expect the optional helper-acquire sidecar in
fixtures without that receipt. The exporter correctly excludes it. No VM,
consumer, storage, cleanup or helper diagnostic observation was produced; no
artifact exists. The original log ZIP SHA-256 is
`2b79f44ed8b67b6af3393cd44e2367e53ec49f3203c26881f406450bfd5b5b0f`.
This failed preflight supplies no new evidence about the earlier runtime faults.

The narrow test correction passes all 17 sampler cases locally and adds this
suite to the hosted source gate: 17 allowed source files and five Python suites
(185 expected cases). Original hosted source run
[`38850938318`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38850938318)
passes on exact `878c2aa9d906fff707a2036873e634800f9253e8`: helper and entrypoint
compilation, 33 Rust and 185 Python cases, strict lint and formatting, with no
failures or skips. All 17 source and 11 unchanged dependency blobs match.
Original artifact and log ZIP SHA-256 values are
`b697cfdff6c49cb74e2f38d6a1b361879690539f2526e42a86256dbba0396419`
and `9777f5f3ba2faef946e5c6c4ac9bb1da6f7f43aad6c5460df5e07917cee4b0c3`.

The subsequent actual run
[`38851643524`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38851643524)
uses that same source, Image `9694a2b9` and Cloud `47b0f03b`, consumer profile 9
and network profile 2. It fails after 52 minutes 31 seconds. The original base
maintenance components validate successfully: restart/resume, foreground
interruption, two restores, replacement/retirement and deletion, with all three
provider usage snapshots zero. That evidence precedes the consumer phase and
does not establish the consumers' remote cleanup.

The first closed consumer failure is Cloud FINALIZE fragment 0/copy 0 at
`stream_open/flow_acquire`, with `CONTENT_UNAVAILABLE`. Two acquisition rounds
report first `helper_kernel`, then `helper_cleanup_incomplete`; no TLS, challenge
or provider outcome is recorded. The combined schema-8 report remains failed,
with maintenance and consumer results absent, and the consumer-v9 acceptance
gate is not reached. The earlier APPEND failure and Image challenge stall remain
separate original outcomes.

The new closed helper sidecar contains exactly one `poll/timed_out` record, with
no errno. Its complete bounded projection corresponds to the helper's existing
5,000-ms connection poll returning zero; it is not a kernel errno. It has no
request/fragment binding and cannot prove which copy or retry produced it, or
why the network connection did not finish. Inspect connection setup, route
lifetime and failure cleanup next, without increasing the original deadlines or
rerunning an unchanged candidate merely to seek a passing result.

The consumer process joins and local fixture cleanup pass. Consumer provider
usage and remote cleanup remain unproven. Guest network-state comparisons and
owned-object cleanup pass; these concern the disposable guest, not a measured
physical-host network snapshot. The runner reaches the final unchanged base-image
hash check after confirmed QEMU stop/reap. There is no separate VM scratch-removal
receipt, so the cleanup trap alone is not independent proof of that removal.
Original artifact and log ZIP SHA-256 values are
`f4e4e24e2e8066d3e71f4f604ff776446d66849983f0216913141e063668288d`
and `e6a573302ce6944f46a280c57f6665b14b948d69b1a1b54007d087d86a5d4359`;
both ZIP CRC checks pass and the artifact matches the API digest.

### Storage connection correlation candidate

The next diagnostic candidate targets the unresolved Image publication stall in
[actual run 38816407455](https://github.com/VOLPAROSSA/volparossa/actions/runs/38816407455).
It observes the client and provider sides of an inner TLS stream without changing
storage wire bytes, permissions or operation deadlines. The recorded candidate
passes corrected hosted source run
[`38837117036`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38837117036):
120 Rust and 267 Python tests, compilation, strict lint and formatting. The
subsequent actual consumer failure is recorded above. This diagnostic is not a
storage fix or consumer acceptance result.

An explicit development-only command on the existing local socket arms a
short-lived, Unix-owner-bound RAM buffer. Client writes and provider reads hash
the same first 64 transferred TLS bytes with a per-fixture epoch. Private epochs
and fingerprints travel only through the collector's private pipes and memory.
The buffer holds at most 64 records; it never evicts active sessions. Missing
observations, terminal eviction and expiry are reported as incomplete. Disarm
clears the buffer and joins its cleanup task; periodic expiry runs on the next
successful cleanup tick, not a guaranteed wall-clock erasure deadline.

The retained sidecar contains at most 32 closed phase/outcome pairs, with no
fingerprints, node identities, paths or application content. A known match may be
retained as `matched_incomplete` when other observations are missing; it does not
establish uniqueness, a fragment/copy binding or the cause of the stall. Normal
and emergency export validate the same bounded schema. Diagnostic failure does
not replace the original consumer result, and final diagnostic cleanup follows
the existing phase-deadline check.

The candidate keeps the original Image/Cloud pins, profile 9 and network profile
2. The 259 local collector, export and harness tests pass, along with the affected
shell syntax and lint checks. The corrected hosted candidate also passes 267
Python tests and 112 unique Rust tests: 50 new cases and 62 historical cases,
with none skipped or ignored. Lint and formatting corrections still need their
own hosted verification before the full storage-maintenance trial on the exact
verified source. Earlier failures and the separate core lifecycle proof remain
unchanged.

The first hosted contract run,
[38834844170](https://github.com/VOLPAROSSA/volparossa/actions/runs/38834844170)
on `77548728a272092d6d5e146b7f603aed5f5fc62a`, passes source binding and the
collector/harness checks, but fails compilation because the new CLI test matches
a boxed command as an unboxed value. Formatting also fails. Rust execution and
Clippy are skipped, so this run provides no Rust runtime acceptance. The follow-up
corrects the test pattern and applies the reported formatting without changing
production behavior, assertions or test budgets.

The corrected run,
[38835678035](https://github.com/VOLPAROSSA/volparossa/actions/runs/38835678035)
on `ce876d1f51f839f7f8e8f6ffdc40e596fbd21ca4`, passes compilation and all
targeted runtime checks. Its source receipt binds the exact checkout and workflow,
35 changed source blobs and six unchanged dependency blobs. The run still fails:
Clippy reports a 102-line serving loop against its 100-line limit, and formatting
requires one multiline assertion. The next correction extracts the existing owned
session body without changing its admission, cancellation or protocol behavior;
it also runs the existing provider-refresh tests alongside the other contracts.

### Execution priorities and next milestones

The shared cache and actual Weather delivery into Drizz.li and Overmorrow are
integrated. The installed Android app now also passes on-demand core delivery,
refresh and background/resume with real products in an emulator. Expiry behavior
has only been demonstrated with synthetic products. Shared private storage maintenance and protected
compute remain the next core dependencies; further Weather expansion does not
automatically take precedence over core blockers. Choose slices by shared dependencies,
architectural uncertainty and a demonstrable end-to-end result, not by application
order or change count. Develop core functions with their actual consumers.

The immediate milestones build on the retained candidates and evidence below:

Core main now contains the native coding backend through PR277. This Storage
candidate remains separate and still requires complete Image/Cloud acceptance.
Original actual trials retain their exact dispatched sources and application pins;
neither source checks nor this diagnostic extension replace those trials.

| Workstream and repositories | Next demonstrable milestone | Dependencies and remaining blockers |
| --- | --- | --- |
| Integrated cache and Weather delivery — `volparossa`, `volparossa-weather` | Preserve the real provider sequence and both joined web-client proofs. | Core PR227, PR229 and PR230, and Weather PR14–PR18 are merged. Drizz.li run `38228710535` and Overmorrow run `38241212407` pass actual acquisition, separate protected cold transfers and exact initial/refresh UI checks. Independent reconstruction, Quality and CodeQL pass. Automatic acquisition, browser-initiated cold retrieval and the complete weather service remain open. |
| Native Overmorrow — `volparossa`, `volparossa-weather` | Preserve actual app-triggered core delivery and verify expiry behavior with real products. | Actual `38717988016` passes on exact core `aac5be7f` / Weather `3b90442a`: initial cold peer retrieval, two cache-backed refreshes, joined native tables, background/resume and cleanup. Source Quality `38714089083` and CodeQL `38714082172` pass. Actual expiry, physical devices, iOS and the complete service remain open. |
| Persistent private storage maintenance — `volparossa`, then Image/Cloud | Resolve the TLS publication blocker, then complete repair, repeated restoration, deletion and confirmed provider cleanup. | Actual `38917106698` still fails Cloud RESERVE at the TLS-handshake deadline. Source `39073538705` on `40348fe5` passes compilation, lint and all 148 Rust/296 Python/50 Node cases, including repeated production-egress reservations; only one formatter hunk fails and is corrected here. Investigate the remaining activated-route/daemon boundary without extending deadlines. Full consumer acceptance and remote cleanup remain unconfirmed. |
| Automatic private uploads — `volparossa`, Image/Cloud | Enroll a new encrypted upload under finite service authority, then resume maintenance and restore it after provider loss. | Core PR233 adds an absolute authorization ceiling; Image PR7 forwards it without rebasing. Cloud PR14 implements finite shared admission budgets, durable reservation/enrollment, restart reconciliation and an encrypted empty catalog for a first upload. Actual OpenCloud SDK upload/list/read checks pass with a synthetic core; this does not prove peer maintenance. Join these candidates to the real upload-to-repair-to-restore trial after the existing storage milestone; its pinned consumers stay unchanged. |
| Native coding execution — `volparossa`, `volparossa-code` | Build on the accepted coding lifecycle and native backend now integrated into core main. | Actual `38824828727` passes on Code `fd4ff968` / core `7d0f9f0b`: two reads, approved edit/test, independent verification, task-resource and input-integrity checks, and cleanup. Code PR11 retains that immutable core pin. Core PR277 integrates the native-only composition after source checks; it does not transfer the model trial to that new binary. General coding quality, competitive performance, native editor UI and protected-peer execution remain open. |
| Protected remote compute — `volparossa`, then Code/Browser | Join an authorized immutable guest, the resident coding worker and a guest-terminated TLS 1.3 session. | PR258's authenticated refusal path has actual route evidence; PR262 integrates explicit same-connection key confirmation. The next implementation reuses the native worker lifecycle and existing TLS stack, rather than extending the probe into task authority. Boot/runtime/model integrity, production roots and current vendor appraisal must be checked before private input; task authority needs its own finite grant. Those functions and actual protected execution remain open; suitable confidential-computing hardware is unavailable. |

Detailed earlier Android and storage checkpoints remain in the
[pre-merge evidence ledger](https://github.com/VOLPAROSSA/volparossa/blob/2f3fa1179373b4e71ed42715bebff9bdc9c4a3ff/docs/IMPLEMENTATION_STATUS.md#android-to-core-integration-boundary).
The latest completed outcomes are summarized below.

### Latest completed integration evidence — 15–16 October

- **Storage retains its base lifecycle proof but stalls during Image publication.**
  [Actual `38816407455`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38816407455)
  fails on exact core `728db40b8b51141652b1e5d7f79d2530e72bb256`, with
  unchanged Image `9694a2b9` / Cloud `47b0f03b` pins. Image FINALIZE
  fragment 0/copy 1 reports `CONTENT_UNAVAILABLE` at
  `challenge_read_verify`, under the operation deadline. Its elapsed buckets
  are under one second before the challenge and 90–120 seconds within it.
  This request reaches the challenge stage, not the earlier flow-acquisition
  failure; that distinction does not establish the cause of either failure.
  Cloud publication is not reached.

  The original standalone lifecycle components validate: core-loss resume,
  a fresh owner turn, two non-consuming whole-archive-verified restores,
  removal of all eleven copies plus the foreground copy, and zero final
  charged/provider usage. The combined consumer report remains failed.
  Local consumer and guest-owned cleanup and the QEMU join are confirmed;
  consumer remote cleanup and provider usage are not. Guest-root-namespace
  snapshots match, but are not host-runner network snapshots.
  Original artifact and log ZIP SHA-256 values are respectively
  `3de6ff71efbdbcbf1447b3fded93143b49462064faad326743b8ec68b3b3a783`
  and `c022af40589f8ef245d60d834b645266e1d9d35e40851739083d461e5c079eef`.

- **Adaptive prefill adds more frequent, honest pause checkpoints.**
  [Actual `38816006720`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38816006720)
  fails on Code `0031c0e9` / core `6d65bb12` with
  `compute_control_ack_deadline`: eight controls were issued and seven
  acknowledged, leaving a pause outstanding. Two reads and one approved edit
  complete; no test command completes. The corrected holder retains task exit
  status and memory counters. These observations do not identify the duration
  or internal cause of a particular native operation.

  Prefill now starts with 16 tokens and adapts subsequent batches toward
  two-second checkpoints, bounded to 1–128 tokens and at most twofold growth.
  The measurement covers only the synchronized native decode, not a subsequent
  owner-requested pause. A pause is acknowledged only after native work joins.
  The complete prompt and retained-prefix rules, model, greedy policy and
  original ten-second acknowledgement deadline remain unchanged. A stalled
  one-token decode still fails closed; this is not preemption or a latency guarantee.

  All 116 inert contracts pass: the 98 existing cases and 18 new scheduling
  cases. They cover complete ordered prompts up to 12,288 tokens, pause/resume
  over real pipes with synthetic native costs, cancellation and absolute
  deadlines. Under the synthetic fast cost, a 5,164-token prompt takes 43
  batches instead of 41; this is not a measured native speed ratio. Native
  C++ and artifact pins are unchanged. Different batch shapes can affect
  floating-point results; bit-identical output is not promised. The real
  coding trial still needs to establish responsiveness, throughput and completion.

- **A real coding task succeeds; its outer postflight still fails.**
  [Trial `38806073909`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38806073909)
  uses exact Code `cce5a211a0624fdcc05a787bd4ff31422b30ae65` and core
  `6d65bb12ed7b8720d43868c9306313133a5b96ae`. Its original task receipt records
  five completed core requests: four function-call responses and a final answer.
  Two reads, one edit and one test command complete; both forwarded permissions
  are accepted. The fixture changes, the original test remains unchanged and
  independent verification passes. No canned model answers or synthetic core are used.

  The task exits successfully after 2,236,512 ms, but the enclosing guest reports
  `stage_failed`. Its task-memory receipt and later `inputs_unchanged` and
  `core_clean_stop` checks are absent. Source review identifies a post-exit
  cgroup-observation vulnerability; the original generic exception does not
  establish which read failed. The correction must preserve the original task
  status and collect real counters before releasing the last task-cgroup owner,
  without extending the existing deadline or treating missing values as zero.

  All five core requests confirm session cleanup. Task runtime/project cleanup,
  guest process cleanup, QEMU/observer joins, scratch removal and restoration of
  CI changes pass. Routes/DNS match under the existing normalization, not raw
  IPv6 equality. This establishes the bounded coding task, not complete trial
  acceptance, general coding quality or private peer execution. Original artifact
  and log ZIP SHA-256 values are respectively
  `8c31054298ef59f0a50c360d4f772afaa010b3c66144e4af85013f49d8565925`
  and `5e21e3f3ec2b6310c58079e81eacb1b35a2cf06858650afa8176463196804d30`.

  The task-holder correction is merged in Code PR18 as `0031c0e9`. Its
  [source check `38815603511`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38815603511)
  passes 533 unique cases with five explicit skips, including all 29 holder
  tests. The holder preserves the original task command and status; the parent
  binds its nonce, peer credentials, task receipt and live cgroup before reading
  actual counters and releasing it. Missing counters remain errors, and the
  absolute task deadline, ordinary tools, model and permissions are unchanged.
  [Actual `38816006720`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38816006720)
  remains bound to Code `0031c0e97f8bd0221c207c5a0f00370073cf617d` and the same
  core `6d65bb12`; it retains the postflight counters but fails on the worker
  pause deadline described above. Complete acceptance remains open.

  Code PR11 now targets main at `8e873c3d1b38c5fab25b6d336aef0dddb1bd2501`.
  Only instructions, Dependabot settings and two documentation files differ
  from the dispatched Code source. Its
  [main-join source check `38817880150`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38817880150)
  again passes 533 cases with five skips; checkout `00abb324` has the identical
  candidate tree `8da080aff2fbb1aa7014e864f294840e5ebc8687`. Original source and
  main-join log ZIP SHA-256 values are respectively
  `849c24d66604b5d0b6cb099da3cc70588959ee58373ccdeada57093e4d0c2331`
  and `0fa8a1b9a1005e9493258e10e6cf9eee6c071cd08927d0d228b841ff09cc9ed6`.

- **Storage reaches Cloud publication and retains a narrower flow failure.**
  [Actual `38804192575`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38804192575)
  fails on exact core `fc75a42d0c458472dc3aeee28311b4e9003803e9`, with unchanged
  Image `9694a2b9` / Cloud `47b0f03b` consumers. Cloud FINALIZE fragment 0/copy 0
  reports `stream_open / flow_acquire`, with two acquisition rounds: first
  `helper_kernel`, last `helper_cleanup_incomplete`. No specific errno or helper
  suboperation is retained. A kernel-category result can also represent parent
  descriptor rejection; it does not uniquely identify a failed kernel call.

  The source-bound Cloud stage establishes that Image creation, deposit, policy
  and enrollment checks, and local core close were reached successfully first;
  it is not a separate Image repair/restore acceptance receipt. The original base
  lifecycle components still prove restart/resume, two non-consuming restores,
  removal of all eleven copies and zero provider usage for that base fixture.
  Consumer-local cleanup and guest-owned network cleanup pass, but remote
  consumer cleanup and usage are explicitly unconfirmed. The complete consumer
  maintenance trial remains failed. Original artifact and log ZIP SHA-256 values:
  `7fb60d72ba2d9efc18582d259697cd9c7e46c80c8d6892119182f4fef0750114`
  and `75f8be9d4e6c622801ed80d04d63a43aa0af4d70731ce7a212f97386f5c44260`.

  Separate source review identifies an availability defect: rejection of one
  newly accepted stream ends the reusable exit listener. Candidate `74f0b16a`
  distinguishes a closed rejected stream from a listener failure while retaining
  fail-closed MPTCP validation, cancellation and failure reporting. Targeted run
  [`38813474802`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38813474802)
  passes all 17 unique tests, including the real kernel-listener test in a
  disposable network namespace, plus formatting and strict Clippy. Its final
  host comparison fails: routes/DNS match, but raw firewall-dump hashes differ.
  Those dumps contain volatile timestamps and traffic counters; the original
  hashes cannot establish whether configuration also changed. The run remains
  failed. A workflow-only correction tests narrowly normalized configuration;
  it does not change the Rust candidate. The predecessor `38813245298` fails only
  two formatting checks before compilation. Neither targeted run establishes the
  cause of the original storage failure or complete storage acceptance.

  The corrected targeted [run `38815471227`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38815471227)
  passes on `ecd99e9c`, tree `2a48c48737ca3396567b932ed3a4dba52096bd71`:
  all 17 unique Rust tests, formatting, strict Clippy, 48 firewall-normalizer
  fixtures and the host-configuration comparison pass. The kernel test preserves
  an existing genuine MPTCP stream and accepts a later one after rejecting an
  ordinary TCP connection. It runs in a disposable network namespace, not on
  the development host. Only recognized firewall timestamps and chain counters
  are normalized; malformed multiline input is rejected and rules remain checked.
  PR265 merges the identical tested tree as `728db40b`. The subsequent
  [actual `38816407455`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38816407455)
  uses that exact source and unchanged profile-9 consumers; its full outcome is
  still pending. Original targeted artifact and log ZIP SHA-256 values:
  `f23e9622fee27e62268f5a4ba10d4f4aa9f57ea460e0196220ebd07c66526a20`
  and `0d20fe1634e35b9b70a1248bcc3deaea8265df7b75c2bd771d13f6f8d453d625`.

- **The native candidate joined to current main passes native source checks.**
  [Run `38811039580`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38811039580)
  checks merge `985774f9fbbec377f90d986fc74ff55ea3adc244`, tree
  `887840a5a8ad3fa5d2fae6259969d04d621420fb`, in draft PR212. Each of normal and
  ASan/UBSan modes passes the same 98 unique Python cases without skips and all
  six native targets, including the complete 35-type upstream tensor suite.
  Twelve source records, eight wrappers and the actual patched CPU compile input
  match Git. All four CodeQL analyses in `38811040412` pass; their build-free
  analysis is not compilation evidence. Full Quality
  [`38811047918`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38811047918)
  passes on a merge checkout with the identical tree: 3,830 unique workspace
  Rust tests pass, with seven ignored. Formatter, strict Clippy, dependency and
  license checks, and the non-mutating harness pass. Three live namespace proofs
  and one optional CLI case explicitly skip; they are not runtime evidence.
  This candidate is not merged into main. The separate original coding trial
  remains pinned to `6d65bb12`. Normal and sanitizer artifact ZIP SHA-256:
  `3ccc0565d589015ff0866afd569cab739fa1b2f017b16d42197a2c24661f3cbd`
  and `19bad8cb5240fc35eb4193fbda9215e6c94a73b45faa731bd83a934b00b809bd`.
  Original Quality log ZIP SHA-256:
  `c2f28db51232f608e9531555086efdb821940c41c5b923d644e85ddb2bff7f1d`.

  The later ledger-only source `a410b015` also passes
  [Quality `38815483235`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38815483235)
  and all four [CodeQL analyses `38815476707`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38815476707).
  Its Quality checkout `93986c0b` has the exact candidate tree
  `1a3e4a1cb48eca5f3031e91b5392f410b0885c50`. Workspace results again contain
  3,830 unique passing tests and seven ignored; six repeated child-process rows
  are not additional tests. Formatting, strict Clippy, dependency checks and
  the non-mutating harness pass. The same unavailable live namespace proofs,
  optional CLI case and separate datapath workflow remain explicitly skipped.
  Only this ledger differs from `985774f9`; these are source gates, not new model
  or protected-hardware evidence. Original Quality and CodeQL log ZIP SHA-256:
  `c6c6b84fa216d6b8fe64239f4074de4ccaf163f9c2a452788c9a00a02b8a4906`
  and `42d1ddadc555872ebf1c641d821ab49774523d9881324c1b9973339b77e3ccba`.

- **The native edit-target correction passes source checks.**
  [Code PR17](https://github.com/VOLPAROSSA/volparossa-code/pull/17) merges as
  `cce5a211a0624fdcc05a787bd4ff31422b30ae65` into the existing native candidate,
  not application `main`. It normalizes an edit permission only when its single
  path, absolute metadata path and running tool input identify the same file
  inside the selected workspace. The original approval policy and all other
  tool permissions remain unchanged. Source review and a regression establish
  this compatibility correction, not the unique cause of the earlier trial.

  [Source run `38805641941`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38805641941)
  passes 504 unique checks with five explicit environment-dependent skips,
  including all 43 new edit-target cases. Its tested merge tree matches the
  candidate merge. Original log ZIP SHA-256:
  `b6a011e3ff6215019f9482e30dcae36d11677f35bf6dcb9feeeda6bb304fcdaa`.
  [Actual trial `38806073909`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38806073909)
  uses that Code revision and core `6d65bb12`, including the source-verified
  eight-file wrapper inventory and Q1 correction. Its bounded task success and
  failed outer postflight are recorded above. Joining the core candidate to
  `main` does not alter its pinned sources or turn earlier failures into successes.

- **The native diagnostic correction passes targeted source checks, not a model trial.**
  [Run `38779519182`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38779519182)
  checks exact core `a37f5cd0b1ec212632dcff95cac4e6da589027e9`: 33 Rust cases
  pass with none ignored, alongside 32 Python collector cases, strict CLI Clippy
  and formatting. The preceding `38778420599` passes the same tests and Clippy
  but fails formatting; `a37f5cd0` applies only its four layout corrections.
  Closed typed failures survive session cleanup without exposing private error
  text or changing admission, deadlines or cleanup authority. This does not
  recover the original failed execution's cause. Original artifact ZIP SHA-256:
  `92c8cfa62486c9ba8b1e3892aaedde955f6052dd51198866bf618558f1719505`;
  log ZIP SHA-256:
  `b8860c039284dff39837f77b97ef789646dd4a06c3c985762f7492c9d07131ed`.

  Paired Code `f23f9c90abe273ce07938b9f7cd5c16409ac52ca` changes only the
  core pin and its test expectation. Its [source CI `38780521264`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38780521264)
  passes 455 checks with four explicit skips; the merge checkout and candidate
  have the same tree. Original log ZIP SHA-256:
  `4400eec4282a7c691928281c0dfa2f85b48c9c5c053cc3a8ff15859061618d87`.
  These are historical source checkpoints, not model-execution proof. The later
  actual trials and current integration state are recorded separately here.

- **Key confirmation is integrated; protected task execution remains open.**
  [PR262](https://github.com/VOLPAROSSA/volparossa/pull/262) merges as `30a40a65`.
  Its final source `798f8c4f` passes
  [targeted checks](https://github.com/VOLPAROSSA/volparossa/actions/runs/38788841314)
  with 97 unique Rust tests and 233 Python tests, without targeted skips.
  [Full Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/38788850703)
  passes 3,728 unique workspace Rust tests, with zero failures and seven existing
  ignored cases; six repeated child-process results are not double-counted.
  Its merge checkout has the exact candidate tree. All four
  [CodeQL analyses](https://github.com/VOLPAROSSA/volparossa/actions/runs/38788843810)
  pass on the final head. Namespace wrappers explicitly skip live proof, so these
  source checks do not establish confidential hardware or private-task admission.

  The preceding Quality run `38783560296` fails in a deadline test that compares
  projections at two different instants. The final test-only correction uses one
  observation instant; production deadlines and budgets are unchanged. Original
  Quality and CodeQL log ZIP SHA-256 values are respectively
  `78195a02e2170f0ac0709c2f07dffef2bb8f672454df1769d56e55d562e61e93`
  and `7e95442ded158971e860d07e2dcd7ef90aebc223c4f65d8e23884d453ccee949`.

- **The preceding coding trial reaches the edit-permission boundary.**
  [Trial `38797816570`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38797816570)
  fails on exact Code `ffc7c3ef88aafd8ffc2c5652dbae5cf598ef9390` and core
  `95ef4541e518f9f9050dedc5d24bd4176b70db71`. All three submitted core requests
  return `function_call`, without request errors. Two native reads complete;
  the edit reaches pending/running states and its one forwarded permission is
  rejected. The task ends with `cancelled_or_deadline`, which does not by itself
  establish that a deadline expired. No edit or independent test completes.
  The unreached final checks leave `fixture_changed=false`,
  `original_test_unchanged=false` and a null resulting hash; those defaults do
  not establish whether the fixture bytes changed.

  Runtime/session cleanup, project and private guest-data removal, empty guest
  units, QEMU/observer joins, scratch removal and restoration of CI changes pass.
  Observed host routes/DNS match under the existing IPv6 reference-count
  normalization, not byte-for-byte. The retained core diagnostics contain no
  errors, and the memory receipts record no OOM kill; these observations do not
  identify the permission rejection's cause. Artifact and log ZIP SHA-256 values
  are respectively
  `0f72837fcf80433ab20588f0f620135f0757c2465f21c9d607dba27f1d587c46`
  and `2d892d31dce74fd3937d53f5e66d63447179591711c2505fcc5e5d71cb56c2fc`.

- **The aligned Q1 source passes normal and sanitizer checks.**
  [Run `38802248241`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38802248241)
  checks exact core `6d65bb12ed7b8720d43868c9306313133a5b96ae`, tree
  `e195dd19eb34fab89daa4535d234e9073fd59ca3`. Both normal and ASan/UBSan modes
  pass all six native targets, including the complete upstream tensor test with
  35 type rows. Each also passes the same 98 unique Python cases without skips:
  196 executions, not 196 distinct tests. Original checkout and end-of-run source
  checks bind all 12 recorded source files and eight wrapper files.

  Build-v4 provenance binds the exact Q1 patch and effective CPU-source hash
  through the atomic `cpu_source_overlay` / `cpu_compile_source_verified` pair.
  Both build logs show compilation of `cpu-overlay/quants.c`; the source-bound
  builder verifies the CMake input against its compilation database. The database
  itself is not retained in the artifacts. The original upstream source remains
  unchanged and the earlier sanitizer failure below remains a historical failure.
  This run loads no model and does not establish memory savings, coding-task
  completion or protected execution; the preceding actual used core `95ef4541`,
  not this correction. Original normal, sanitizer and log ZIP SHA-256 values are
  respectively
  `64504e7594e6795a443629d71e279ee5020347d49695e1ef3a039730cf5de1ba`,
  `a821e619fb480763ae2be3f269c32e1b3fd4b34bc5777535fb10256415705d44`
  and `331a3389729df0cd185470dd9c770e3d9e3bf27a61c92246608e827345c1824f`.

- **The earlier native coding trial identifies the memory guard.**
  [Trial `38788802469`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38788802469)
  uses Code `a15a55243679cd6749ae7a1f2bab0919fbc05237` and core
  `01c90c574cf3e0e39a90aa7931a90b7c37811995`, after their source gates pass.
  The single admitted request returns `compute_memory_budget`: the supervisor's
  10 GiB sum-of-process-RSS limit, not an observed cgroup OOM kill or request
  timeout. The last retained generation observation records a 4,572-token prompt
  and one generated token. No tool call, edit, independent test or successful
  model turn completes. Runtime/session cleanup, private project removal, guest
  units, QEMU join, VM scratch removal and CI host restoration are confirmed.
  `original_test_unchanged=false` reflects an unreached final check, not evidence
  that the test changed. Artifact and log ZIP SHA-256 values are respectively
  `f62286861c3c2fa2148797c9ea86e6ce1ba1df8eeeb22fdc3319d02c5dc0c6b8`
  and `77cfdd6766530fb33d5107768767c807007d4a213e24fb37e6690002a40187b7`.

  Source review identifies avoidable initial KV-cache allocation: the retained
  session reserves the full 13,312-token context, while this complete prompt plus
  its existing output allowance needs 5,632 padded tokens. In the pinned BF16
  implementation that difference is 1,080 MiB. This is a source-derived saving
  opportunity, not proof of the exact overshooting RSS sample. Candidate
  `95ef4541` sizes the context for the complete current prompt and output
  allowance. Growth destroys the old context before allocating a larger one
  around the same model; that turn refills the complete prompt rather than
  reusing its old prefix. No resource limit, model, toolset or accepted context
  length is reduced or enlarged.

  [Source run `38795606001`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38795606001)
  passes all six normal native targets and all five owned sanitizer targets,
  including the new capacity ABI and ten session-transition test groups. Both
  modes pass the same 91 unique Python cases without skips; repeating them in
  two modes does not make 182 unique cases. Exact source hashes and post-run
  source checks pass. The upstream all-type sanitizer target still fails at
  `quants.c:590`; its failure tail is byte-identical to run `38759834612`.
  The total sanitizer result remains failed. The implicated Q1_0 kernel is
  outside the selected BF16/F32 path, permitting a bounded normal-mode experiment
  without claiming full native acceptance. Actual model execution, observed
  memory savings and complete coding behavior still require that experiment.
  Original normal, sanitizer and log ZIP SHA-256 values are respectively
  `10482199f2a789e08ced3391777aad6b06d91995d6ed141eeef1bcc3a7d73b6a`,
  `a1228f80fd11f58f2e78c76b808cd3bbbaf5137ddff2453fcb070276566b0062`
  and `434e92a6916e8e7d7ba0856e8165c4f02df05d49766a89714371f039c365a5ad`.

  Code `ffc7c3ef` changes only its two core-pin literals. Its
  [source check](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38797117801)
  passes 455 cases with four explicit fixture/source skips; the merge checkout
  and candidate have the same tree. Original log ZIP SHA-256:
  `8081e1b880f28e72cb83ad6052c54101aff4d90b8b43e549046434a32a80d617`.
  The paired [actual trial](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38797816570)
  subsequently failed at the edit-permission boundary recorded above, with the
  same full toolset, BF16 model and resource bounds. These earlier source results
  remain historical evidence; later Q1 correction and coding outcomes are separate.

- **Storage flow diagnostics pass their complete targeted source gate.**
  [Run `38799870413`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38799870413)
  on exact `0e17aff5ac8232829023512a857e73359af44639` passes 167 unique Rust
  tests: 27 new cases and 140 historical cases, without failures, ignores or
  skips. Strict all-target/all-feature Clippy for the three affected packages
  and workspace formatting pass. The original checkout, 24 recorded source
  files and six dependency/toolchain files match; dependency pins are unchanged.
  Artifact and log ZIP SHA-256 values are respectively
  `e9f9b27e81b655dcf6e534dfee60be27cd1b29f128e6e48eaf1ce3f49654e70c`
  and `b783aee43b5746ea2e7d2d5e72f4d9144e28abe968ff771f9a2e952a3bf311a1`.

  The earlier
  [run `38792234897`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38792234897)
  on `eb92bae7` passes all 27 new cases and 61 historical cases, with no failures
  or ignores. It then stops before historical CLI execution because Cargo's
  substring filter includes an unrelated compute module. The strict inventory
  check correctly refuses those 21 extra cases. The workflow correction keeps
  all 77 intended historical CLI cases and the strict scope/count checks.

  [Earlier run `38794822447`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38794822447)
  on `14a512b3` passes 167 unique Rust tests: 27 new cases and 140 historical
  cases, without failures or ignored tests. Strict Clippy then rejects three
  missing code markings in API comments; the formatting step is not reached.
  Artifact and log ZIP SHA-256 values are respectively
  `58bc36cf3e0d40e2869121600ef2ef925d6381d0a48aa54e287897fca19a2621`
  and `b523a498b59a3f1ec0d45a39faf0f55957f46dd5a4358a7385acff18d701cd77`.

  Earlier runs `38792234897` and `38793350071` stop after 88 and 165 passing
  tests because Cargo's substring filters include unrelated compute modules.
  The corrected inventory keeps all 77 historical storage CLI cases and both
  intended control cases, with the original strict scope and count checks.
  Earlier failed runs
  `38783188054`, `38789158345` and `38790196633` respectively expose an undeclared
  test dependency, missing EOF readiness in a fixture and a real cross-subcommand
  diagnostic-option conflict. Their focused corrections remain in history.

  Image `9694a2b9` and Cloud `47b0f03b` publish the same opt-in adapter, with
  69 and 20 targeted tests passing respectively. Consumer profile 9 pins those
  exact sources and carries only bounded typed diagnostics; old report versions
  remain separate. The combined candidate
  `fc75a42d0c458472dc3aeee28311b4e9003803e9` passes full
  [Quality `38800337179`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38800337179)
  on an exact direct checkout. Workspace tests pass 3,947 unique cases with zero
  failures and seven existing ignored cases; six repeated child-process results
  are excluded from that count. All 27 new cases pass, as do the isolated outcome
  and wire suites with 10 and 37 cases, and 276 consumer checks. Formatting,
  strict Clippy and the non-mutating harness pass. Three unavailable live
  namespace probes and one opt-in local CLI check are explicitly skipped.
  Original Quality log ZIP SHA-256:
  `10f6d39bfcc3162ee64d60204941e9ca125fa46fa174ae41fc342e6ddb6dcbaf`.
  These source/component checks do not prove that the underlying acquisition or
  Cloud-catalog failures are fixed. [Actual trial `38804192575`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38804192575)
  ran once on the same `fc75a42d` source with the existing
  `private-storage-maintenance` scenario and failed during Cloud publication,
  with the original failure and cleanup boundaries recorded above.

  Its earlier first full Quality run `38793812077` on `779e4f2c` passes
  the 276 storage consumer checks (228 Python and 48 Node), then stops at Rust
  formatting before `check-shell.sh`, Rust compilation or workspace tests. Revision
  `de8b9719` applies the original formatter's 19 hunks and the three comment
  corrections without changing runtime behavior. The subsequent targeted and
  full Quality acceptances are recorded above; these earlier component checks
  are not another actual storage trial or proof that acquisition is fixed.

  [Run `38796320282`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38796320282)
  on that revision again passes all 167 cases, then reaches one further Clippy
  finding in the observation test's negative `if/else` layout. The focused
  correction puts the positive condition first while preserving both branch
  bodies and every assertion. It changes no production code or test budget.
  Artifact and log ZIP SHA-256 values are respectively
  `1761ae75f0414f3a39df31f5735ff5e9f3e39d296fa8f87f1b305c03e393a1c4`
  and `4e8009c367d3beb1fb045244b4ee2c9993cecef1f48726aa10d67266ba643b9a`.

  [Run `38798034905`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38798034905)
  on `56683ab4` again passes the same 167 unique cases, then Clippy identifies
  a 29,576-byte future in the actual Unix-transfer diagnostic test. Revision
  `0e17aff5` uses `Box::pin` around that future, in the same task and diagnostic
  scope; the test body, assertions, production code and limits are unchanged.
  Formatting is not reached in that targeted run. Original artifact and log ZIP
  SHA-256 values are respectively
  `a71aaff913b899cbaf0a2d607740634a659b465dd77764f036888048fbfe7ebc`
  and `ec46f1b9f6a8f579c023405c6f7a51dbf04fdba63b2d6c56e8462b667d105b59`.
  Profile 9's separate [Quality run `38798321440`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38798321440)
  on `42c1710c` reaches the same Clippy finding after passing formatting and
  shell checks. Its original log ZIP SHA-256 is
  `93f7fa12fcf490b63b43c6733f69149fc6213a052f92cf1b39f269897e4fa8b9`.
  The same two-line test correction is included in the later accepted source
  candidate and original actual trial recorded above.

- **Same-connection key confirmation passes targeted source checks.**
  [Run `38781307814`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38781307814)
  checks exact `6bc319254499994971efdab61909d89e0df2ff7a`: 97 unique Rust
  tests and 233 Python tests pass, without ignored or skipped cases. Formatting
  and strict Clippy for the four affected packages pass; the original checkout,
  final source tree and lockfile match. Original log ZIP SHA-256:
  `a5b7e86ea68c2690c6420488823a944f2a32a4bb0f9fbb553788e44fa6a573fc`.

  The explicit profile retains the original verifier owner through reference
  verification, a fresh encrypted random probe, its signed echo and the final
  correlated acknowledgement. It preserves legacy negotiation and refuses
  unsupported confirmation instead of downgrading. Possession is separate from
  approved key origin, complete appraisal and private-task authority; the
  [command contract](development/PROTECTED_COMPUTE_VERIFIER.md#explicit-key-confirmation)
  keeps those limits explicit. This checkpoint preceded the full source
  integration above; actual hardware execution remains outstanding.

  Earlier source attempts remain failures, not additional acceptances.
  [Source run `38775482837`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38775482837)
  on `64ddee26` passes formatting, 16 guest cases and 48 quote cases. One new TLS
  fixture fails with `BrokenPipe` when the client closes after the provider has
  already dropped its in-memory endpoint. The remaining crypto, agent/CLI and
  strict lint gates are not reached. Revision `9ddd5849` changes only the fixture:
  both peers retain their endpoints until the other's TLS close notification is
  read, under a five-second bound. Run `38776287805` then exposes an incorrect
  expected protobuf tag in the new selector test; `c98af13d` corrects the test,
  not the production selector. Runs `38777738731` and `38779304338` pass all
  97 Rust cases but stop at strict Clippy. The subsequent fixes remove those
  findings without suppressions; the successful run above verifies the result.
  Synthetic report facts remain test-only; these tests cannot prove actual
  confidential hardware, complete appraisal or private worker admission.

- **The paired native-session trial fails before a completed tool action.**
  [Trial `38771413590`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38771413590)
  uses exact Code `266d1a03f0b327cc7221610372a8c626fe4b50d9` and core
  `0de65f423a6d96fa565facf6f283efae70adf2bd`, after their source checks pass.
  Pinned model provisioning and native build-v4/backend-v3 construction complete.
  The single submitted request ends with `execution_failed`; no tool call, edit
  or test completes. The fixture is unchanged. A retained worker observation
  records one generated token after a 4,572-token prompt; it does not prove a
  successful model turn or prefix reuse. The task and worker timers have different
  starting points, so their difference is not an observed acknowledgement timeout.

  The task diagnostic is `unclassified`. Source review finds that the session's
  failure wrapper hides its cause from the closed diagnostic classifier. The
  accompanying `cache_hint / supervisor_error` records the failed supervision,
  not a demonstrated cache operation failure. Preserve typed error categories
  without exporting private error text; the original execution cause remains
  unknown. The final receipts confirm runtime cleanup, project/private guest-data
  removal, empty owned units, QEMU join, VM scratch removal and restoration of
  CI changes. Observed host routes/DNS match semantically and byte-for-byte.
  Artifact ZIP SHA-256:
  `4dcedc22d678a0516b89d6ffd1d213ead188ab5e58827d94396a47857d19a0fa`;
  log ZIP SHA-256:
  `c3825b4f3de24599ad20dbf14499dc556dbefb5aa43173af6c4e3c2b262457cc`.

- **The new Storage trial stops during Image publication.**
  [Trial `38766434111`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38766434111)
  runs exact `324581656fdddab71b803d279e31d58796281be6` with unchanged consumer
  pins and limits. The primary failure is `image_publish / publish_operation`:
  fragment 2, copy 1, FINALIZE receives `CONTENT_UNAVAILABLE` at
  `stream_open / flow_acquire`, before provider TLS. `deadline_scope=none` and
  `agent_outcome=null` do not identify a timeout, capacity shortage or helper
  failure. Existing acquisition code collapses several typed errors into this
  category; the original receipts cannot distinguish them. The earlier Cloud
  catalog phase is not reached and its failure remains unresolved.

  The separate base lifecycle still passes restart/resume, two restores,
  removal of all 11 retained copies and zero provider usage. Consumer client
  close and local fixture cleanup pass, but consumer remote cleanup and provider
  usage remain unconfirmed. Guest-owned network objects are removed and the
  guest's root-network state is unchanged; QEMU join is source/log-bound, without
  an independent post-removal scratch receipt. Ten rounds of provider sampling
  do not establish a cause. Artifact ZIP SHA-256:
  `ecb4c8a11001c0255ff0cf33281649fcefdd687372c20b20db2b224ea86f9f74`;
  log ZIP SHA-256:
  `554736e19eca50f94aed61a81e6df24c0fa5257a11e944c5a18acad37326d7b3`.

- **The protected route carries an authenticated hardware-unavailable refusal.**
  [Trial `38766299588`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38766299588)
  passes on exact `2ed91039317dc45db69bc4ddf20560042e0a41e4`. The intended
  requester receives the closed device-unavailable report, verified by its local
  agent; the command still exits unsuccessfully and grants no worker admission.
  Wrong-requester and repeated requests exit without output and each produce one
  fresh signed-exchange failure. The fixture grant permits one attempt for at
  most 600 seconds; the provider's fixed quote device is genuinely absent.

  Both selected relay paths carry WireGuard data on both legs, through the same
  exit/context; the provider receives requests and sends responses. Captures
  finish without drops or truncation and observe no direct client-to-exit or
  unexpected provider traffic. This small exchange does not prove bulk payload
  on two MPTCP subflows. Provider detach/stop, route disconnect and guest cleanup
  pass. The guest topology's root-network state is unchanged; the independent VM
  receipt confirms QEMU join and removal of private guest state.

  The two original reports pass their validators. Artifact ZIP SHA-256:
  `a2d3b25fa7ea53dcdf7e52dc6d38749a6c50c3ca21c41eb650a4919cbf36d37c`;
  log ZIP SHA-256:
  `f7adbaa95918db058cd2e05bba544296a1b1f3b5221c608f57d3ce5bb370da02`.
  This proves the bounded refusal path, not hardware attestation, a portable
  provider signature at the CLI, current vendor appraisal, release of private
  input or protected task execution. Historical public certificate fixtures are
  not production appraisal authority.

  [PR258](https://github.com/VOLPAROSSA/volparossa/pull/258) integrates this slice
  as `7120914524c807c775ade306dd6cec7913a22068`. Quality `38764678234` passes
  on merge checkout `64de0331ef3d5a5ed88537f1e8d11fdae21c722c`: production
  sources match `2ed91039`; differences are two documents and the previously
  reviewed Android symlink-atime test correction. Workspace tests pass 3,688
  cases with seven ignored; three live namespace checks and one opt-in CLI
  harness check are explicitly skipped, not counted as live-route proof.
  Original Quality log ZIP SHA-256:
  `e13a91e8a1d7f6f036e912c87aa3a1e5a4c6b3e1e5f97ff663ce3a08e08ce52f`.

- **The preceding native coding trial completes two reads, not the requested edit.**
  [Trial `38742699743`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38742699743)
  uses exact Code `8b21775e072d3182b3766622fd387208992786a1` and core
  `3327115e07d2c4fa976b2d0c625729a68df0aaf6`. Code source run `38741853989`
  passes 438 checks with four explicit skips. The actual run admits three model
  requests: two return tool calls observed as completed native reads; the third
  ends with `compute_deadline`. The fixture is unchanged and no edit or test is
  verified. Its last worker observation records 4,987 prompt tokens, first forward
  completion at about 585.6 seconds and 26 generated tokens near 595.8 seconds,
  within the unchanged 600-second request budget.

  The bounded host observer records pressure against the existing 13 GiB QEMU
  limit, but zero OOM/kill events. This does not identify the sole cause of the
  deadline or explain the earlier lost VM. Worker and QEMU joins, private guest
  state and VM scratch removal, observer join and runner restoration are checked.
  Observed routes/DNS are semantically unchanged; raw IPv6 route output is not
  byte-identical because the existing comparison excludes reference counts.
  Original artifact ZIP SHA-256:
  `721d57778d0dd5f2bc259921f9cee24caaa0d2a98fc094d35c21f4a3cb1ed4da`;
  log ZIP SHA-256:
  `5b03fddfa33dcf2d4514598297cdcdf06b5e9d66ec024ff5c06123fb3dc2ee98`.

  The candidate in core PR212 and Code PR11 retains the model and exact prompt
  prefixes within one owner connection/task. It separates per-request file
  removal from final worker/private-state cleanup; private KV state is not shared
  across owners or projects. Code `97dfa4ad` passes source run `38759140548`
  with 455 checks and four skips. Core `00a4d73b` passes 83 targeted Rust checks,
  including all 21 new session cases, before three Clippy errors stop Quality
  `38763979390`. The corrections end at `0de65f42`, which passes full Quality
  `38766972432` and all four CodeQL analyses in `38766966694`. The original
  Quality checkout `9396878dd99326439619b759a14661086604b4d1` has the exact
  candidate tree `3d54c5aaff167396ca691971be70fc3b0274ac29`. Its seven ignored
  Rust cases, three unavailable namespace probes and one opt-in CLI harness
  skip remain separate from passing source checks. Original Quality and CodeQL
  log ZIP SHA-256 values are respectively
  `067ff87e054b732e3c9a7d048939330f4ec34a2fc83ac49657884cf909093ddb`
  and `c07d075eeb8268d983b48aa294597c202340b57baacdecb693c57316d4d562cf`.

  Code `266d1a03f0b327cc7221610372a8c626fe4b50d9` changes only the trial's
  core pin and its literal test expectation to that revision. Its inert native
  contract check passes 43 cases, including import of the exact retained core
  builder; one test requiring separately retained patched loader source is
  explicitly skipped. It loads no library or model. The paired actual task is
  still required to prove model loading, prefix reuse and the complete coding
  loop; source checks are not demonstrated acceleration or protected execution.

  Native C++ run `38759834612` on `2439892e` passes all six normal targets and
  five sanitizer targets, including the session checks. The upstream all-type
  tensor target then fails with an unaligned `uint32_t` load in `quants.c:590`.
  That run is a failure, not an all-sanitizer pass or evidence of actual model
  loading and prefix reuse.

- **The preceding Storage trial reaches the catalog phase.**
  [Trial `38746134861`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38746134861)
  runs exact `ec56c9f68534b983072570cd1ddf79f82d86ad7a`, after Quality
  `38740632723` and CodeQL `38740626654` pass. The original report correctly
  rejects the combined scenario with `CONSUMER_APPLICATION_FAILED`; its consumer
  receipt says `application_failed`, last stage `cloud_catalog`. Source ordering
  places that stage after the Image and Cloud deposits, but the same stage also
  covers catalog restoration/decryption/validation, policy reading and the final
  client close. The retained code does not distinguish the failing operation.
  This is not evidence that the preceding intermittent TLS/APPEND failures are
  fixed, nor permission to replace uncertainty with a transport diagnosis.

  The restored provider observer records 17 rounds / 51 observations without
  sampled long-running operations; sampler and children are joined. Sampling
  cannot exclude missed activity or prove a cause. Original base receipts still
  pass restart/repair, two restores, removal of all 11 retained copies and zero
  provider usage. That independent reconstruction is not a combined acceptance
  record. Guest/local fixture cleanup and bounded QEMU join pass, and observed
  host-state files match; consumer remote cleanup remains unconfirmed. There is
  no independent post-removal scratch receipt. Original artifact ZIP SHA-256:
  `afed0b65363668384fd5a5f2cd8edec4447cda0260ac262d428123de82092eb6`;
  log ZIP SHA-256:
  `17516efa2cb211a4bef5c2eca52cb61bd20a5a0e9bc84c36138bdfb06395efb4`.
  Candidate `32458165` now freezes the primary failure before client cleanup and
  distinguishes catalog preparation, creation, validation and policy reading.
  Its separate `publish_cleanup` result concerns only the client's `close`, not
  remote deletion or provider usage. It exports closed codes, not private paths,
  metadata or exception text. Quality `38762587601` and CodeQL `38762581523`
  pass on that exact candidate, including the 43 Node and 46 Python diagnostic
  checks. The subsequent [actual trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/38766434111)
  retains those pins and limits but fails earlier, during Image publication, as
  described above. Cloud's separate
  upload-to-maintenance actual stays gated on combined Storage acceptance.

- **The preceding quote-route trial fails at the wrong-requester check.**
  [Trial `38761419244`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38761419244)
  runs exact `c6ac459011766408b90ee6ea15583efe6f394c7a`. Its original guest
  report records `QUOTE_WRONG_REQUESTER_NOT_REJECTED`, exit status 1 and no
  accepted route evidence. Guest-owned cleanup reports zero remaining objects;
  the separate VM receipt confirms QEMU join and private guest-state removal.
  The absent route evidence does not establish unchanged host state or reveal
  the failing CLI response. Original artifact ZIP SHA-256:
  `338b39020dfeb3972406b52a7314d01d2a6c585021d903289b94240709b30b27`;
  log ZIP SHA-256:
  `87fc81011353823be3d81993ac34d85e74fa26e5f2956f28a7bb5239b56c3807`.

  The fixture creates three public inputs as root, while the CLI's existing
  reader requires the executing user's ownership. Candidate `2ed91039` assigns
  only those files to the fixture worker, at mode `0400`; the production guard
  is unchanged. This source-proven mismatch is not a recovered runtime error
  from the failed trial. Targeted run `38764669492` passes 233 Python and 55
  Rust checks, formatting and strict Clippy; CodeQL `38764671761` also passes.
  The subsequent actual passes as described above; it does not retroactively
  supply the missing failure diagnostics from this earlier run.

- **The preceding Storage trial fails during Cloud FINALIZE.**
  [Trial `38731855117`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38731855117)
  runs exact `1db29f62809b9360d5c6acb31b0b0fa128190479`, after Quality
  `38727088626` and CodeQL `38727084357` pass. Its combined report correctly
  fails Cloud publication at fragment 0/copy 0, operation `finalize`, stage
  `agent_ready`: the agent reports `tls_handshake` / `handshake_deadline`.
  The enclosing deadline scope is `none`; `agent_outcome` is null. No payload
  timing or transport cause can be inferred from that result. This is not the
  preceding APPEND receipt-read failure.

  The original base receipts pass the lifecycle checks for restart, pause/resume,
  replacement, two restores and removal of all retained copies. Reconstructing
  those checks is not a new published acceptance record and does not complete
  the combined consumer scenario. Guest-local namespace and consumer-fixture
  cleanup pass; consumer remote cleanup and provider usage remain unconfirmed.
  Exact wrapper ordering and its final image check establish the bounded QEMU
  stop and join, unlike the earlier timeout. The Storage wrapper does not emit
  an independent post-removal scratch receipt.

  Provider event-ring coverage cannot prove absence or correlation. A separate
  activity sidecar is missing because the source enables its existing observer
  for consumer profile 7, not the selected profile 8. Correcting that wiring
  restores observation; it does not fix or explain the handshake failure.
  Original artifact ZIP SHA-256:
  `7620dfff47184fec77b7747d1f4f8a620b06bb80b74bd96a05b3f2f9a2ade3dd`;
  log ZIP SHA-256:
  `070ba2d91ff5368a0f5c5365df01a440f8992f6c2441b0b0bb19941eecf24b02`.
  The exact source, closed diagnostic versions and both ZIPs are independently
  checked. Cloud's separate upload-to-maintenance actual remains gated on this
  combined Storage milestone; no duplicate trial is started.

- **Cloud upload integration passes source checks, not actual maintenance.**
  [Quality `38730435481`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38730435481)
  passes on `f91958bd5eacc365898dbcd0c7a5c6fb86b454a3`, including the five
  finite-enrollment authority cases, formatting, strict Clippy and workspace
  checks. Namespace and optional harness skips remain skips. The candidate
  binds the updated consumer profile and preserves original upload authority
  across restart; this run does not perform an actual upload, peer replacement
  or cold restoration. Its original log ZIP SHA-256 is
  `5194964ff8e1773a96b9d303cfad77b2194591665f22f4c5588ab21bc694607c`.

- **The preceding native coding trial loses its VM before guest evidence returns.**
  [Trial `38737284583`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38737284583)
  uses Code `3a5c1f59b282952e378e9525f2cf47da43ee19b2` and core
  `3327115e07d2c4fa976b2d0c625729a68df0aaf6`. Core Quality `38733078778`
  and CodeQL `38732695543` pass; Code source run `38733022967` passes
  410 checks with four explicit skips. The actual trial's prepared source,
  build and preflight checks pass, then the QEMU unit reports `oom-kill` and
  signal 9 during `guest-inference`. SSH exits 255 and no guest result is
  recovered. This proves neither the deciding memory boundary nor whether
  model preparation, the new worker cache hint or model execution was reached.
  The fixed QEMU limit remains 13 GiB with swap disabled.

  QEMU join, private VM scratch removal, unchanged observed host routes/DNS,
  runner restoration and build cleanup are confirmed. Guest-internal worker
  join and private-data cleanup cannot be separately confirmed without the
  missing result. No successful edit, test or protected execution is claimed.
  Original artifact ZIP SHA-256:
  `031678c85a91bc8210c5dff121b8a1037cdb31e9519bc5a19cfdd36ce39d0cf2`;
  log ZIP SHA-256:
  `358264ace79ac02eee6d355a8d095a0245b20d5ed14623a5bad14af48c480d39`.
  Independent audit checks both source trees, bundled files and original ZIPs.
  Its follow-up candidate adds bounded host-cgroup observations without changing
  model, task, limits or disk-cache configuration.

  The preceding [trial `38726624377`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38726624377)
  on Code `4fc36928` / core `2dd38983` has a different outcome: one actual
  read, a second admitted request cancelled by the memory guard, then five
  admission refusals. It records no OOM kill and no edit or test. Its guest
  memory observations are not evidence about the later lost VM.

- **Actual Android-to-core delivery passes in an emulator.**
  [Trial `38717988016`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38717988016)
  passes on core `aac5be7f602fae9754153cdcb5c401ecb9ee7cb6` and Weather
  `3b90442a9d5be4db73ccf83cba2028364980c3ca`, after exact-source Quality
  `38714089083` and CodeQL `38714082172` pass. The installed Overmorrow app
  initiates cold retrieval of real weather and air-quality products through the
  core. Original receipt, HTTP-response and native-table hashes are joined for
  all six requests: three per product, with four weather rows and five air-quality
  rows. Initial peer transfers carry 12,282 and 8,774 bytes; subsequent requests
  reuse the cache. All six record zero origin bytes and zero origin range requests.
  Actual taps trigger refresh; the app then backgrounds and resumes with the
  same still-fresh products and no additional product requests.

  The original closed validators and final acceptance reconstruction pass.
  The 39 admitted inputs match the exact v6 manifest; all 20 Weather source
  files are also checked against their Git objects. Packet checks bind both
  products to one capture window, require two different selected relay paths
  and reject direct client-to-exit traffic. They do not establish bulk distribution
  across two simultaneously active subflows. Private HTTP bodies, UI records and
  captures were validated inside the disposable trial, then removed rather than
  exported. Owner children and QEMU are joined, private guest state is removed,
  and the original 77-byte KVM ACL is restored exactly. Original artifact ZIP
  SHA-256: `7a3f92eb5d921267ecffaeff82215bb2b6f32e9a3cdcfbf5d349a8eb7cae0232`;
  log ZIP SHA-256:
  `fab33fb1e4baf8fbb0339dcb682f810d36f4ee63e77eba64e811520c74e03ee9`.
  This proves the scoped joined delivery, not expired-product recovery, visible
  pixel rendering, physical-device operation, iOS or production authority.

- **Earlier Android failures remain part of the evidence.**
  [Trial `38693605028`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38693605028)
  on core `75da4143` / Weather `3b90442a` records successful actual installed-app
  execution and zero native/tunnel exit statuses. The owner rejects guest-driver
  exit status 1 during final evidence verification. The closed diagnostic names
  `android-guest-evidence`, not the particular failed assertion. Owner/VM cleanup
  and exact KVM ACL restoration pass; joined delivery and actual expiry do not.
  Original artifact ZIP SHA-256:
  `b1087779bdcc541d2400aa7f2ca40180620cdebfc6e24d238449eb865e3afb85`.
  Candidate `8967006e` retains the verification statements and exposes only a
  finite failure-group code. [Quality `38701451204`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38701451204)
  passes its 388 inert Android checks, formatting, Clippy and workspace gates
  on the exact candidate tree. Explicit namespace and optional-test skips remain
  skips. [Actual follow-up `38705213351`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38705213351)
  on that core and unchanged Weather source fails with `android-evidence-source`
  during final guest verification. The installed-app trial still reports success;
  owner children and QEMU are joined, private guest state is removed and the exact
  KVM ACL is restored. Original artifact ZIP SHA-256:
  `16b637e010230f91abfeedb5bb0bec4ad6c4f509b76e673bc13e607552666c7c`.
  The source group includes a verifier that permits root/current-caller ownership,
  while the admitted Android tree is deliberately owned by fixed worker UID 985.
  Correction `2125c41d` adds a root-only, exact-worker verifier with manifest hashes,
  modes, complete file/directory inventory, no-follow descriptors and identity
  rechecks; the old caller verifier is unchanged. All 164 relevant inert checks
  pass, including 57 in the two changed suites independently rerun. They reproduce
  the ownership incompatibility, not the deleted private inputs of the failed run.
  The merge with bounded VM shutdown passes 18 Android wiring, 25 lifecycle and
  four VM diagnostic checks. These source checks preceded the passing actual
  trial above; neither result proves actual expiry.
- **Storage publication and hosted shutdown have separate failures.**
  [Trial `38688661444`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38688661444)
  on `b7e63589` retains a passing base restart/resume, replacement, two-restore
  and delete lifecycle. Cloud publication fails at fragment 0/copy 0 APPEND:
  `wire_receipt`, with the original operation deadline expiring during
  `remote_receipt_read`. This is a total operation budget, not a measurement of
  time spent waiting for the receipt. Forty valid activity snapshots per provider
  and a provider APPEND payload-I/O event are retained; they have no request
  correlation and do not identify the cause. Guest namespace and local fixture
  cleanup pass; remote consumer cleanup and provider usage remain unconfirmed.
  The job later exceeds its 150-minute limit after guest results are retrieved.
  Hosted QEMU exit, join and scratch removal are therefore unproven for that run.
  Its wrapper permits a 40-minute poweroff SSH command followed by an unbounded
  child wait; PR255 subsequently corrects that lifecycle, not the APPEND failure. Original
  artifact ZIP SHA-256:
  `5396980d373740b36a99e263c7b9af2d6fb0761d6403598b87c72a1fef39cde3`.
  A separate signed nested-TLS regression on `b2f699e8` passes
  [run `38709817601`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38709817601):
  reserve, two APPENDs, finalize and read-back over the production proxy/TLS path
  return verified receipts before stream closure, with small duplex buffers.
  The one test, formatting and Clippy pass; production code is unchanged from
  `b7e63589`. Artifact ZIP SHA-256:
  `fae5bc388563ef197169139df27006754bca6df0cc6af59e3b0a644fdcbe607d`.
  This component regression is not a live MPTCP/Cloud proof or a cause for the
  failed APPEND. The source candidate below separates time before payload, local
  write/flush and receipt read, alongside bounded provider read-failure codes;
  those observations have not yet been collected in another actual Storage trial.
- **OpenCode reaches one real read, then refuses memory admission.**
  [Trial `38695131367`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38695131367)
  on Code `7f451e67` / core `3630ff79` passes native build, conversion and
  provisioning. One of seven submitted requests produces a function call and
  the actual OpenCode runtime completes its read. The six subsequent task events
  report `compute_model_memory_headroom`. This identifies an admission refusal,
  not whether host memory, a cgroup ancestor or unavailable measurements caused
  it. The reported core memory peak is 8,706,998,272 bytes under an
  11,811,160,064-byte limit, with zero OOM kills. Neither the admission sample nor
  invocation/outcome of cache advice is retained. The task ends after 588,327 ms
  without an edit, test or changed fixture. Reported runtime, project, VM and
  owned-runner cleanup complete.
  Original artifact ZIP SHA-256:
  `f194f9d173436c95818ea2bcdca2327c35bea8a2d3896c65329c563508e1d5c1`.
  Core `60a7386b` subsequently passes full Quality `38705500842` and CodeQL
  `38705495404`, including the 42 targeted Rust cases. Code `0c28e818` pins it
  and passes 410 source checks with four explicit skips. The following actual
  [trial `38709341304`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38709341304)
  again completes one read and refuses six requests, with no edit or test.
  The first refusal's original sample reports self-cgroup headroom 9,844,887,552
  bytes below the unchanged 11,274,289,152-byte requirement; host availability is
  11,650,129,920 bytes. The single bound model-cache advisory succeeds, but the
  subsequent sample still charges about 1.94 GB as file cache to that cgroup.
  This establishes the admission input, not which files remain charged or that
  all those pages can safely be reclaimed. No OOM kill occurs; reported runtime,
  project, VM and owned-runner cleanup complete. Original artifact ZIP SHA-256:
  `364b548f95fa0ca9db0d65757698ec67f8b581fb6e000eecc6e5783cc44f654f`.
  Model, task, CPU and memory limits are unchanged; the remaining cache/lifecycle
  cause needs investigation rather than a weaker admission guard.

See the follow-up results in [Storage PR232](https://github.com/VOLPAROSSA/volparossa/pull/232),
[Android PR248](https://github.com/VOLPAROSSA/volparossa/pull/248) and
[Code PR11](https://github.com/VOLPAROSSA/volparossa-code/pull/11).
Only an audited completed follow-up supersedes an earlier outcome within its
tested scope; starting a run does not.

### Storage profile-8 source candidate and preceding gates

[Targeted run `38718864739`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38718864739)
passes on exact `ab0e5471b368b3f7806abab2402faf905ca82403`: 99 unique Rust
tests, including all 22 new APPEND cases, and 82 Python tests pass; relevant
Clippy and formatting gates pass. The original direct checkout and all 25 changed
source blobs match that head. This is bounded contract verification, not a
complete workspace or distributed Storage acceptance run. Original log ZIP
SHA-256: `4f497d861341bb315b64528fa35580e68809570677e35ce87055bcb8aecfe21e`;
artifact ZIP SHA-256:
`a73dbf46c6ab5ff6862e190470ad5a4abb261095e9d5ac702ba53b682ab0ff99`.

Explicit consumer profile 8 pins Image
`10c46b9d6424929748e324fdd188a2f5ca77851a` and Cloud
`dda7a21818ece774445cf63d6e9a01fe0f2803b2`; their adapter suites pass
62 and 16 tests respectively. Both use the same reviewed adapter bytes,
SHA-256 `d5c1bf8695dc7b154b8fcb4b0ebde8af5764aa2bc779a60c8fab324c8c84b7ea`.
Only this trial's configuration opts into CLI diagnostics 7, consumer observation 8
and node result 9; the adapters' defaults stay unchanged. Provider export 3
retains only finite APPEND header/body I/O categories; client timings use the
original operation clock. Historical profiles 1–7, deadlines, retries and
acceptance remain unchanged.

Before final profile-8 staging, local checks passed 126 core consumer-harness,
83 outer-report and 41 wiring cases. The first integrated
[Quality run `38721329999`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38721329999)
on `a8d85d5df028019d48c085d3bedce025cae5d438` instead records **249 passes
and one failure**: the valid preflight fixture omits the newly required v8
manifest, so production correctly rejects it with status 69. Later formatting,
Rust, Clippy and isolated Storage gates did not run. Correction `16692f1e`
adds that manifest only to the test fixture and retains its missing-file and
symlink rejection checks. All 41 wiring checks pass locally after correction.
The original merge checkout `bf5b04ded184c1b943209ab746b6f8f747e1e3c1`
has the exact candidate tree `49c1127919e7cf4c349d3bcc2209b6a1dc0331a7`.
Original log ZIP SHA-256:
`1c137b5c0318484860863ba95faa3ae2aeefb168fe88a98c2a166af915ee4f76`.

[Quality `38722691110`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38722691110)
on corrected `16692f1e37d5ccb67f1073b8bec3e0cfe5c6b806` passes all 250
consumer checks, 25 QEMU-child checks, eight VM-diagnostic checks and the 12
focused streaming tests. Formatting and dependency gates pass. Strict Clippy
then stops at compilation error `E0308` in the service test fixture: it still
declares `File`, while the integrated directory helper returns `Flock<File>`.
Workspace tests, the 22 new APPEND cases in that workspace, lockguard regressions
and both isolated Storage groups did not run. Original merge checkout
`b180ce5ec40d4fb13b7cea46918310558783ea16` matches the exact candidate tree
`567ca3e99c8d1aebede1302be32be37c6a89a942`. Original log ZIP SHA-256:
`69c4ca4769d0b3fc029e986f5c237dd9923ba113125529e5e89908d32871e2e8`.
CodeQL `38722687582` passes all four jobs on the same source; its log ZIP
SHA-256 is `77e14a3f440d6013fc392d03e688dd197f14c637e7303a61f15309f32c7ac5eb`.

Test-only correction `13ae582a6cb9e8abaedb3fc7af68240d1599cf10` changes the
fixture's return type to `nix::fcntl::Flock<File>`. All five callers retain the
same guard lifetime; no production lock, cloning, unwrapping or admission rule
changes. Integration with main `c985560e80a9f15e0ccc90ad73d9a6062beecd94`
preserves the Storage complete-JSON and deduplication export rules alongside
the Android truncation guard. Source gates for this combined candidate remain
required. No new actual Storage trial has started, and the original Cloud
APPEND failure remains unexplained.

The earlier bounded-shutdown integration passed 25 QEMU-child and eight
VM-diagnostic checks. Nine consumer-shell checks also passed and are already
included in the consumer totals above. Its ShellCheck comparison found no new
diagnostics against the pre-merge source, but existing diagnostics remained;
this was not an unconditional ShellCheck pass or an actual Storage cleanup proof.

### Native cache-release source gate and retained failure

Candidate `3146d2b4` fails
[Quality `38719959058`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38719959058)
after all 62 targeted Rust tests pass, including the 20 new source-weight cases.
Strict Clippy rejects one permission-mask expression and three test expressions;
workspace and namespace acceptance did not run. Original log ZIP SHA-256:
`e7ad3e067ce089134304aa55a4df86962290088d111dd51d1dcfaf59e8cbc498`.
Correction `2dd38983` subsequently passes Quality `38722825812` and CodeQL
`38722771032`. Its original Quality checkout matches tree
`df09af3b8b7adf4d6332535ebd9bbd63e39dc56b`; all 62 targeted native tests pass
(20 new source-weight cases and 42 existing cases). Seven intentionally ignored
tests, three namespace skips and one optional harness skip are not live proof.
Original log ZIP SHA-256:
`2ed2fbefcca2a847cb0310d32169eb280c16f6a0a22c7d1493cb44d082598dde`.
Code `4fc36928` passes source run `38722953808` with 410 checks
and four explicit skips. These are source checks, not proof that cache release
repairs the actual coding task. The last audited actual outcome remains one
read and six memory-admission refusals in `38709341304`; no edit, independently
verified task test or confidential peer execution is established by these gates.
[Follow-up actual `38726624377`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38726624377)
has started on Code `4fc36928` / core `2dd38983`; its result is not yet established.

### Explicit native CPU inference candidate

#### Connection-bound model reuse candidate

Earlier Code trial `38742699743` on core `3327115e` / Code `8b21775e`
completes two native reads, then reaches the third request's compute deadline.
No edit or test passes. The candidate retains one model and exact processed
prompt prefixes within a single owner connection, with the normal full toolset.
The new [versioned session contract](../crates/volparossa/src/compute/private_conversation/WIRE.md#connection-bound-native-sessions)
separates per-request file removal from final worker/private-state cleanup.
No state is shared across owners or projects; failed admitted requests are not
replayed. The 600-second request ceiling and pressure/memory guards remain;
the resident worker has a separate 2,400-second task lifetime and cumulative CPU
ceiling, with 300-second idle closure and at most 128 requests.

Core `2439892e` passes all six normal native source targets in
[run `38759834612`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38759834612).
ASan/UBSan passes the ABI, loader, BF16/F32, output-constraint and session targets,
then fails the pinned upstream all-type test at `quants.c:590` on a misaligned
load. The overall sanitizer result remains failed. The
[source-bound audit](https://github.com/VOLPAROSSA/volparossa/pull/212#issuecomment-6195934792)
verifies all seven wrapper hashes; these synthetic tests do not prove actual
model loading, KV reuse or acceleration.

The core's 164 inert Python cases pass. Code `97dfa4a` passes 455 source checks
with four explicit skips in
[run `38759140548`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38759140548).
Core Quality `38759968511` stops at formatting before Rust tests; `d6d7c4d3`
applies its eight exact layout corrections. This historical checkpoint is
followed by full Quality on `0de65f42`, the failed paired actual trial and the
closed-diagnostic correction in the
[latest evidence](#latest-completed-integration-evidence--15-october).
Complete coding execution and confidential peer work remain open.

#### Source verification lifecycle candidate

[Actual trial `38726624377`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38726624377)
on Code `4fc36928` / core `2dd38983` remains incomplete: one completed read,
a second admitted execution cancelled by the unchanged memory guard, then five
memory-admission refusals, with no edit or test. Its last observed substage is
`tokenizer_load/complete`; no later `prompt_encode` record is retained. Runtime,
project, guest and VM cleanup are confirmed; protected peer execution and general
coding quality remain unproved. The [original audit](https://github.com/VOLPAROSSA/volparossa-code/pull/11#issuecomment-6191437311)
retains the source bindings and artifact digest. Aggregate file-cache counters do
not identify individual files or prove reclaimability.

The new candidate retains only the three source-shard descriptors used by the
complete hash verification. After successful source, configuration and dataset
checks and an owner-control check, it attempts at most three file-bound cache
advisories before GGUF preparation. Metadata binds those descriptors; it does not
replace content hashes. Existing post-supervisor hints and all resource guards
remain unchanged. Twelve inert cases exercise the real small-file hash and
descriptor sequence, failure rejection and cleanup; they do not prove reclaimed
memory or a completed model trial.

#### Earlier memory-admission follow-up

[Actual Code trial `38695131367`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38695131367)
on Code `7f451e67` / core `3630ff79` completes one native OpenCode read, then
refuses six requests with `compute_model_memory_headroom`. No edit, test or
fixture change occurs. The core peak is 8,706,998,272 bytes under an
11,811,160,064-byte limit, with zero OOM kills. The original records do not show
the admission sample or whether cache advice was invoked; they do not identify
the cause of refusal. Original artifact ZIP SHA-256:
`f194f9d173436c95818ea2bcdca2327c35bea8a2d3896c65329c563508e1d5c1`.

The next candidate observes the original admission sample and finite cache-advice
outcomes only for explicitly diagnostic native private-conversation runs. Host,
self-cgroup and ancestor headroom remain the same fail-closed decision inputs.
Optional memory statistics are read afterward; they are neither available-memory
estimates nor proof of reclaim. No cgroup names, paths, prompts or model output
are exported. The existing cleanup, single advisory syscall, result, model and
resource limits remain unchanged. The collector keeps its default v1 shape and
adds a bounded v2 memory record list only when requested. All 31 inert collector
tests pass, including an independent rerun. These observations are not a causal
fix or completion of the coding task or protected peer execution.

Initial hosted check `38702380046` stops at formatting, before Rust tests. Its
source-bound formatter artifact supplies five layout-only corrections in four
files; the temporary artifact step is removed after applying them. Artifact ZIP
SHA-256: `e4471084d545a26e9aa1850cee46a270cf1cbe06e93590dfb6f22201662065cb`.
No local Rust compilation or formatting runs.

[Quality `38702928794`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38702928794)
on `0091e75f` passes formatting, 60 native Python contracts and the targeted
Rust suites: 28 native/cache-hint, seven admission and seven sampler tests,
including all sixteen new cases. The collector's 31 checks pass on the hosted
runner as well. The original merge checkout has the exact candidate tree.
Strict Clippy then rejects a similar variable name and a literal `unwrap_err`
in a test; workspace tests and subsequent gates are skipped. The correction
renames only that binding and explicitly matches the expected error while
retaining the original error-text assertion. Full Quality is still required.
Original job-log ZIP SHA-256:
`47fce1d4bc03c78984c4e3e78b2a8c8cfaacb7e8e927df28203c6f35f526b748`.

Code `8b214da1` pins `0091e75f`, opts into these closed native observations and
retains the existing 256 KiB public-export ceiling. Torch's diagnostic calls
and 64 KiB guest-receipt limit remain unchanged. Its exact-source
[CI `38703873328`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38703873328)
passes 410 tests with four explicit skips. No new model trial has run; Code
must first pin the corrected core and pass the required source checks.

#### Tool-call output constraint candidate

- [ ] Continue the existing native OpenCode integration after actual Code run
  `37683661957` on Code `45510055` and core `9e9086ee` produced one invalid JSON
  tool-call body. That run proves no usable turn, tool action or coding result;
  it does not identify a unique cause inside generation.

The new optional `qwen_tagged_tool_json_v1` profile binds IPC negotiation,
owner-authorized backend manifest v2/build v3, the actual serialized dataset,
core-derived offered-tool aliases, worker request and returned result. The
native ABI preserves the old unselected greedy path. Selected requests allow
ordinary answers, or one tagged JSON tool call with arguments nesting at most
16. The strict final parser remains authoritative: no output repair, forced
tool use, prompt truncation, extra time or alternate model is introduced.

171 targeted inert Python checks pass, including a serialized selected dataset
through the actual worker/encode/decode path with a synthetic native executor.
That test caught and corrected a cross-layer input-field rejection.
[Hosted Quality `38672934132`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38672934132)
on exact core `9d044921` passes formatting, strict Clippy, 60 native Python
contracts and all thirteen new Rust manifest, request/result, parser and IPC
binding cases. The workspace records 3,558 distinct passing tests and seven
ignored tests. Three namespace proofs and one optional CLI identity proof are
explicitly skipped, not successful datapath evidence. Original job-log ZIP
SHA-256: `7760651e167a4700b0967c19dca7c6755b3a71e463799658faac3f372d576571`.

Earlier Quality `38671767972` on `030c16f0` stopped at strict Clippy's
`if_same_then_else`: two adjacent identical rejection branches became one
equivalent disjunction, without suppressing the lint or changing admission.
Run `38671600105` stopped at formatting before Rust compilation; `030c16f0`
changes only those seven formatting hunks. These source checks are not proof
of a complete OpenCode coding task or protected peer execution.

[Actual Code trial `38675278393`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38675278393)
on Code `6aa6291a` / core `9d044921` passes native build, conversion and model
provisioning with the selected output constraint. One of seven submitted model
requests completes with a function call, and the actual OpenCode runtime
completes one `read` action. Six requests return `execution_failed`; none is
reported as invalid output or an execution-budget error. The only retained core
event is `result_observed`, which does not identify the six failures' causes.
The task ends after 588,147 ms as `opencode_task_incomplete`: no edit, test,
complete native turn or successful coding loop is proved. Its read-state
counters describe observed transitions, not three distinct tool calls.

Reported runtime, project, provisioning-group, guest-unit/private-data,
QEMU/scratch and owned CI-host cleanup complete. Scoped normalized route/DNS
observations match; raw IPv6 route bytes differ, so this is not byte-identical
host-state evidence. Raw model output remains excluded. Original artifact
`11946278747` ZIP SHA-256:
`487bee78bb4857c6a5b48df7d69df21ceeb608ded9d9264122668480f62afa74`;
original job-log ZIP SHA-256:
`5ff8a4055bf966f192f80b366cbeb8428d77793c6ee6525b3109eecf292af36e`.

The next diagnostic candidate observes failed private-service tasks after the
existing cleanup-slot decision, including errors before worker supervision or
after report validation. It uses the existing opt-in local diagnostic target
and an exact closed list of setup/result-binding codes. Unknown errors remain
unclassified; raw errors, paths, prompts, request identities and model output
are not exported. Wire responses, cleanup/cancellation precedence, retry policy,
model, resources and acceptance are unchanged. This is not a fix or a causal
explanation for the six observed failures.

The core's closed collector passes 23 Python checks. Three new Rust tests cover
real pre-supervisor admission failure, report rejection, logging enabled/disabled,
privacy canaries and unchanged cleanup/cancellation behavior. All three pass in
[Quality `38678859785`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38678859785)
on the direct checkout `5607f1177dc230a71414e7468c221b950f43bca6`, together with
all thirteen output-constraint Rust cases, 60 native Python contracts, formatting,
strict Clippy, the workspace (3,561 distinct passes, seven ignored) and non-mutating
harness. Skipped namespace proofs remain skips, not datapath evidence. Original
job-log ZIP SHA-256:
`60e43c4a0a63a250b4af601245d9e41772135149e47663a730a511866347d1b9`.
Earlier run `38678595442` stopped at one test assertion's formatting; `5607f117`
corrects only that layout. Its skipped Rust steps are not passing evidence.

Code `e39267343612ed8b594d15db3e161465c25b8c2f` now pins this verified diagnostic
source without changing its model, resource or acceptance settings. The pin
change passes 103 targeted Python checks with two explicit retained-source
skips. [Code source CI `38681259931`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38681259931)
also passes: 405 checks and four explicit skips, including a missing-runner-bwrap
synthetic namespace check. All 114 source blobs in merge checkout `3580a655`
match the candidate. Original log ZIP SHA-256:
`0b9d42a5f0526ada26cf56166b2698d48b83510a3d6ffb5d5950a113d3b9e93c`.

The [actual follow-up `38681471469`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38681471469)
on that Code/core pair completed with one read and six memory-admission refusals.
It preceded the cache-advice candidate and the latest trial above; neither
established a successful coding loop.

[Source-only native run `38671551374`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38671551374)
on `b8bd8228` passes the normal build and all five check targets. ABI, loader,
BF16/F32 and the new output-constraint tests also pass under ASan/UBSan. The
unchanged upstream all-type test then fails on the already recorded unaligned
Q1_0/Q8_0 load at `ggml/src/ggml-cpu/arch/x86/quants.c:590`; the full sanitizer
job remains **failed**. The selected converter and model adapter admit BF16/F32,
not this quantized kernel. This narrower evidence supports the next bounded
development trial, not a clean upstream sanitizer result or release readiness.
No model was loaded and no local Rust, native build or inference ran.

The normal build's v3 manifest binds the six wrapper sources, exact upstream
tree and library SHA-256
`3e59444d6f81c753ab1fcd3418ebabfb42f0368b24c76961ee59ddaf339617fa`.
Native sources, Python contracts and workflow are byte-identical between
`b8bd8228` and `9d044921`. Original normal artifact SHA-256:
`40ecaab5262d043a25b3d30d52a641f8406130103741e00d6857eca925201163`;
sanitizer artifact:
`3c948ae71d8c54870fe1a151b95d699556aa0907f9ccd17b5a9d3d18d71b5272`;
job-log ZIP:
`21b840e5ec8c39d8e7af2d9b23214b6eb1a5b04f324343fd57386a6ab8d21dde`.

Initial source-only run `38671269423` on `4e5126ad` stops before compilation or
build-log creation in both modes. The original preflight resolves CMake to
`/usr/local/bin/cmake`, while the scrubbed build PATH excludes `/usr/local/bin`.
The generic builder failure does not retain its internal exception, so missing
CMake is a source-supported diagnosis, not an exported error code. Preflight and
build now use the same fixed hosted PATH, without installing anything. No native
check passed in this attempt. Original job-log ZIP SHA-256:
`f05e248ac6685079055b8a4db631d43b85ded5792be0d53a2374ce446c0e0177`.

#### Earlier native candidate evidence

- [ ] An owner-selected `llama_cpp_bf16_v1` backend is being connected to the
  existing isolated private-conversation worker. The source-only build of pinned
  llama.cpp `7fe450e19305b828c199d602c23a8337aaa1f03b` passes. Actual conversion
  and provisioning pass. The historical unselected-output trials include
  `compute_deadline` during post-generation verification and `invalid_output`;
  neither proves a usable native turn or successful OpenCode coding task. The
  selected-output follow-up above now proves one model-driven read action,
  still not a complete coding loop. All original failed trials remain below.
  This first backend accepts only the original Qwen3-4B-Instruct-2507 profile and
  explicitly negotiated `greedy_v1`; public jobs, training and other profiles
  retain their existing backend. It does not establish confidential peer execution.

The fixed owned native ABI receives the complete original tokenizer-rendered
prompt in bounded prefill batches, not a shortened prompt or smaller/quantized
model. Conversion must compare every original tensor value; BF16 matrices stay
BF16, while required norm tensors are exactly promoted to F32 and reported as
`bf16_with_exact_f32_norms`. AVX2, FMA and F16C are explicit CPU requirements.
An owner-supplied manifest digest binds the native library and converted model;
peer data cannot choose executable code. Artifact verification precedes loading
inside the unchanged network-isolated sandbox. Deadlines, owner-priority controls,
cleanup confirmation and original model-result checks remain required.

Six inert Rust authorization/result-binding checks, fifteen private-service tests
and five sandbox tests pass. They cover absent legacy fields, restricted native
admission and cancellation/cleanup contracts, not real model performance. Actual
conversion, complete inference and the unchanged native OpenCode coding scenario
must pass before this path is described as working end to end.

The definitive normal source-only build records library SHA-256
`4af8d584349d184049c5f6ffea3e5618839c69536676a6bb5c12ef33b03755a7`
and build-manifest SHA-256
`d51c06798cae305622cf91089692c323cc31c1af8ff63420b270aaf44830d27c`.
Twenty-five native Python contract checks and thirteen targeted provision/retry
checks pass. They include the explicitly selected, exact SentencePiece converter
dependency without changing the original 38-wheel runtime; its native extension
adds one wheel. Real harmless subprocess tests cover timeout, cancellation,
cancellation racing a successful wait, and outer SIGKILL followed by the owned
process-group cleanup. No converter child detaches into a new group. These are
not actual model-conversion or inference tests.

The first [candidate quality run `37233543544`](https://github.com/VOLPAROSSA/volparossa/actions/runs/37233543544)
on `d2fe6728` remains failed: strict Clippy rejected the permission-mask spelling
(`verbose_bit_mask`), after formatting and the nineteen original native Python
checks passed. The equivalent `trailing_zeros() >= 6` spelling preserves the
requirement for zero group/other permission bits. All six native Rust tests pass
again; no assertion or privacy boundary was removed. Retained decoded job
`111528060483` log SHA-256:
`80dbe57d6b939c97c41785c4b7473fd2cc218daa197f017b4157b92501399685`.
Skipped later steps are not passing workspace or datapath evidence.

The subsequent [quality run `37235233676`](https://github.com/VOLPAROSSA/volparossa/actions/runs/37235233676)
on `f7e2c3b9` passes strict Clippy, but **fails** four full-command-tree tests:
the flattened native argument structure and its parent both use Clap's default
`Options` group name. The other 578 binary tests pass; later namespace/integration
steps are skipped. All four CodeQL analyses pass separately. Original job
`111532896805` log SHA-256:
`227fc42e300b3515506ebed4f3abab453222bb70659dadef9ef53772b9e35126`.
No native model trial was dispatched on that failed candidate. Correcting the
argument-group identity must retain the paired owner options and all existing
admission rules; source-only CLI checks are not model-execution evidence.

The follow-up gives only the flattened native options an explicit, unique Clap
group identity. Nine targeted native tests pass, including full-command-tree
validation, both-or-neither owner flags on `run` and `private-serve`, unchanged
explicit execution, and rejection of native flags on `private-task`. The four
original failing command-tree tests also pass locally. The new command-tree test
was observed failing before the correction. These checks do not replace the
exact-source CI or a disposable native model trial.

Core `7308371b20ced0504662178beb0e46586cfc9d2d` subsequently passed its
source checks. The first native Code trial `37239050033` stopped during source
build without retained resource/manifest evidence. Its bounded ready/release
follow-up on Code `01c5c591b16ed34226341e04fe673a35a7a169de` and the same core
reached a completed source build in
[trial37614132814](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37614132814).
The live helper's verified library and manifest were retained before successful
exit; observed build peak was 1,031,565,312 bytes, with zero swap/OOM.

That original attempt remains **failed** at model provisioning with the closed
category `native_conversion` and process status 1. Wheel-graph/runtime-import
checks passed first, but the catch-all conversion marker does not identify which
conversion check or subprocess failed. Build resource counters do not describe
the later conversion. No model provisioning, inference or coding-task success
is claimed. Reported guest units/process-group/private-data and outer QEMU/scratch
cleanup passed; the scoped routes/DNS comparison remained unchanged.
Original artifact ZIP SHA-256:
`d4b32d66e90d4c76568b2fa989cbab5e49bbb736283868a03a81f9ae0303a254`;
job `112768290137` log SHA-256:
`6e561f75a15560a56f3d98c1a49e518c52ad543646ea1463c7f475e5ec2d0ce6`.
The follow-up retains a closed conversion stage, failure category and bounded
child exit status without exception text, paths or raw converter output. The
legacy failure marker remains. Twenty-nine native/conversion fixture tests pass,
independently repeated by root, including inert injection at all thirteen stages
and child failure, timeout and cancellation. Quality runs the new tests as part
of the existing native contract step. This is diagnostic coverage, not a model
conversion fix or permission to rerun the same failed attempt.

The exact diagnostic follow-up on core `7739206361aa0aeb7cf0b20d9f8cf1cc9da5c81b`
and Code `61d2c0c52468eee7728cf6f32a107baca5bae240` also remains **failed**:
[trial37623495917](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37623495917)
reached verification after the converter exited with status zero. Its closed
diagnostic reports `stage=verify`, `failure=contract`; it does not identify the
first rejected assertion. No model was admitted and inference did not run.
Reported process/unit/private-data and QEMU/scratch cleanup passed; the scoped
route/DNS comparison was unchanged. Original artifact ZIP SHA-256:
`50ad3ba19fe9811e132f2dad7ee3c49407d5fcecc86a65a816d7a0637eab996e`;
job `112799334236` log SHA-256:
`24bcefeb3279b24e011008fecca2037a0808dac2af82587527c1d378759c86a3`.

Independent source review found a verifier incompatibility: the pinned Qwen3
converter omits `rope.dimension_count`, while its loader defaults that value to
the explicit attention key length. The follow-up checks that effective rotary
dimension, key length and value length all equal the original model's head
dimension. Wrong explicit overrides and every missing required field still fail.
Tensor values, model pins, tokenizer checks and resource limits are unchanged.
This is a source-proven correction, not proof that it was the first failing check
in the original trial or that full model conversion now succeeds.

The following exact-source [trial 37631532611](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37631532611)
on Code `8a7034d5e09cf34f8ac67742f347eb657f769440` and core
`10fd16dc78a0c91dee627b9d8bdab2226f2cc415` **fails during execution**,
after a successful source build, conversion and model provisioning. The verified
original BF16 GGUF contains 8,051,283,488 bytes (SHA-256
`d7934f6fa06f9781bc15540f0e2b83f89b1895e86440a4e97af4f0434311d1bd`).
The worker reaches `verify_files/begin` and then reports
`compute_control_ack_deadline`: an I/O-pressure pause was issued at 19.12,
but only the preceding resume was acknowledged. Source review found no owner
control checkpoint in the full-weight hash loop or subsequent native bundle and
post-execution verification. The follow-up processes controls on the execution
thread between the unchanged 1 MiB hash reads, including initial preparation,
native bundle validation and post-execution rehashing. Every original byte,
digest comparison, pressure threshold and deadline remains required. All 138
focused worker/native tests pass, independently repeated by root; real files and
owner-control pipes prove pause/resume, cancellation without a partial result,
unchanged deadlines and tamper rejection. A single blocked read or other
non-cooperative operation can still exceed the existing deadline. This is a
tested control-path correction, not a successful repeat large-model trial.

No native model turn or tool call completed. Six OpenCode requests failed within
this one workflow, all with cleanup confirmed; no workflow retry was dispatched.
Core peak memory was 2,303,844,352 bytes, with zero OOM kills and swap. Reported
unit/process/private-data/QEMU/scratch cleanup passed; scoped host-state files
match and no raw model output was exported. This is conversion/provisioning
evidence, not inference, successful coding or protected peer execution.
Original artifact ZIP SHA-256:
`78c4732774fc93dae9872df0460e2addf7f3849a6a190f803069fbc7d6a6e9c8`;
job `112826781182` log SHA-256:
`ef7d5c7bbeeebf497ec9a42881746a782b36f7c7bddc9febef11d7af373cb44f`.
All earlier failed trials and their consumed dispatch receipts remain preserved.

The owner-responsive verification [trial 37641148934](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37641148934),
attempt 1 on Code `d48801a6` / core `773d6377`, also **fails**. Source build,
conversion and provisioning pass with the same full BF16 model. The retained
state now records all 20 issued controls acknowledged and reaches
`model_load/begin`, but ends with the closed `worker_other` diagnostic. The
receipt does not identify the native load failure's exact cause; no native turn,
tool call or coding task completes. Six failed runtime requests have confirmed
cleanup. Core cgroup peak is 8,106,295,296 bytes against 11 GiB, with zero swap
and OOM kills. Reported owned-unit, process, private-data, QEMU and scratch
cleanup passes. Normalized route/DNS observations match; raw IPv6 route bytes
differ in the excluded counter column, so byte-identical host snapshots are not
claimed for this run. No raw model output was exported.

Original artifact `11492792961` ZIP SHA-256:
`b2621c8918f1304848fcc4a7b9e736fab2379cdf19c29de9ab11606e5c9e9cfc`;
job `112860150266` log SHA-256:
`4e32650af9e373e5e28ec93663777f1fe833feee419a5fe604fcfdfa6b7ec438`.
The consumed one-shot helper and receipts remain unchanged. Progress beyond
file verification is not successful model loading or inference.

Source inspection found that the upstream loader starts one asynchronous
validation task per tensor, independently of the two-thread inference limit.
The new loader-only patch defers both validation paths to one execution thread
and polls the existing owner callback between tensors. It preserves all checks,
error aggregation and the final completion callback; cancellation rejects the
entire load. This removes a demonstrated source hazard, not a uniquely proved
cause of the historical failure. A single tensor check remains non-interruptible.

The original checkout and notices remain unchanged. Build manifest v2 binds the
original tree, patch and effective loader digests and verifies the staged source
in the compilation database. Old build manifests and absent diagnostic accessors
are refused. Native errors now retain only fixed model/vocabulary/context/sampler
phase codes through the worker, core and fixture; private exception text remains
excluded. A fresh source-only build passes four check targets, including 398 tiny
F32 validations through both actual patched launch paths, invalid-tensor rejection
after complete checking, cancellation and fresh retry. Its build manifest SHA-256
is `884bdbd00ad7cbcf1211b468d2835bf1e4b9edee2081cb6758712b3703ed0769`;
check log SHA-256 is
`adf689f10f35ebdeaf42f47d997e3496809f1683788d7dd7eacb1085622a5510`.
One hundred twenty-five focused worker tests and twenty-one diagnostic-fixture
tests pass, independently repeated by root. No patched model-loading or inference
trial had run at that source-only checkpoint, and no resource limit or task was
relaxed. The subsequent actual trial is recorded below.
The fixed-code Rust diagnostic test also passes on CI's Rust 1.85. Independent
source review and a repeat of the actual tiny validation harness found no blocker.

Native sanitizer evidence is mixed and remains explicit: the owned ABI smoke
passes, but the unchanged upstream all-type tensor test **fails** under UBSan on
an unaligned `uint32_t` load in the Q1_0/Q8_0 dot product. That quantized path is
outside this BF16-only candidate, but the full test is not waived or relabeled.
Its original log SHA-256 is
`37e07701e4f9a7fadbee0876f77d7eb034192e951a4cd2da572606255bf84f08`.
A separate ASan/UBSan target reuses unchanged upstream F32/BF16 test functions
and tolerances; its 18 F32 vector cases and three BF16 checks pass (log SHA-256
`6fac1d1773ae750583092ed00014e40983d319811a67afea385cc014fe514e46`).
This is scoped kernel evidence, not a passing complete upstream suite or model
inference. Sanitized build artifacts cannot be provisioned as production models.

The subsequent [trial 37654339995](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37654339995),
attempt 1 on Code `8b5d5b6a` / core `f4cd8bd7`, remains **failed**. Native source
build, conversion and provisioning complete. One submitted model request returns
one cleanup-confirmed incomplete result (`invalid_output`); no usable turn, tool
call, permission request or completed command is observed. The provider reports
`invalid_model_output` once, with zero `execution_failed`, token-limit and
wire-truncation events. Core records `result_observed` once and
`conversation_native_json` twice: the latter are two validations of the same
report, not two executions. The tagged tool-call body failed typed JSON
deserialization, but the historical closed code does not distinguish syntax,
schema/type, duplicate fields or incomplete JSON. No raw model output was
exported, and no unique prompt, template or model-loading cause is established.

Core cgroup peak is 4,555,878,400 bytes against 11 GiB, with zero OOM kills and
swap. Task-memory and graceful-core-stop fields are absent; they are not zero or
successful observations. Reported owned units/process-group/private data and
outer QEMU/scratch cleanup pass. Normalized route/DNS observations match, while
raw IPv6 route hashes differ; this is scoped observation, not byte-identical host
state or a complete firewall audit. Original artifact `11499080343` ZIP SHA-256:
`c7d3ed9150e8eb8e7d58a65ed46b0179c997a74f2191c621cf0109552278b6dd`;
job `112905525075` decoded log SHA-256:
`fd62b12408eee3e4bbf6c994a84a9cede4fd088806103525782cf428f1ff6610`.
The original archives, logs and consumed receipts remain unchanged.

The diagnostic-only follow-up separates Serde's closed JSON error categories
(`syntax`, `data`, `eof`, `io`) after the unchanged report binding. Historical
generic codes remain readable. It exports no parser message, field name, source
position or output fragment and leaves `invalid_output`, single-call acceptance,
the complete prompt/model and every resource/deadline bound unchanged. This is
source-level diagnostic coverage, not a repaired model result or passing coding
trial. No new model execution had run at that checkpoint; its subsequent actual
trial is recorded below.

The diagnostic follow-up [trial 37671030306](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37671030306),
attempt 1 on Code `2b2687fec5376b6e49f8266dff71cc7935845e99` / core
`36d616fb6d79a36fe7c8ee95c4ad84bd56b561ae`, **fails at the execution
deadline**, not at the earlier JSON rejection. Build, conversion and provisioning
complete. The worker records 44 generated tokens and an internal generation
completion at 518,788 ms, then `verify_after/begin` at 519,120 ms. Its last state
is paused under `quiet_hold`, with all 31 issued controls acknowledged and pause
as the last acknowledgement. Core reports `compute_deadline`; the provider
records one cleanup-confirmed `execution_budget_exceeded` request. Internal
generation completion is not a verified result delivered to OpenCode.

The task ends after 603,331 ms with zero completed native turns, observed tool
calls, approved reads/edits/tests or completed commands. The fixture is unchanged
and independent verification is not reached. Core cgroup peak is 9,466,974,208
bytes within 11 GiB, with zero OOM kills and swap. These checkpoints do not measure
total pause time or establish a unique cause of the deadline overrun. Reported
runtime/project, guest-unit/private-data, QEMU/scratch and owned CI-host cleanup
pass. Normalized route/DNS observations match, while the raw byte comparison is
false; this is not byte-identical host state or a complete firewall audit. No raw
model output was exported.

Original artifact `11505764017` ZIP SHA-256:
`935e115a86abf1da83fe0e3d68ebac90d37ecbe399c7dcc79f055ff26dc33e83`;
job `112962546447` original raw log, 68,786 bytes, SHA-256:
`369407954fff82728d2ff41d5d0e229c78726ea8ae487bf2112964138ca492d8`.
The log is retained without decoding or newline normalization. Earlier failures,
original receipts, model/task checks and resource/deadline bounds are unchanged.

The next source candidate makes native verification scope explicit. Native
inference reads the converted GGUF, not the original conversion-source shards.
The worker retains the actual complete initial shard/aggregate measurement and
fully verifies the used GGUF before loading and after closing the native handle.
It no longer reads the unused 8,044,982,000 source bytes a second time after
generation. The PyTorch execution-weight checks remain unchanged.

A mandatory closed `verification_scope` in the internal native report states
this distinction; Rust rejects old reports, missing scope and extra or different
scope. Conversion tensor checks, complete GGUF hashes, model identity, owner
controls, resources and deadlines are unchanged. The focused Python and Rust
contract checks and independent source review pass. This removes redundant work,
not the failed trial: **a new complete native turn and OpenCode coding scenario
still need actual execution evidence**. See the
[verification contract](../crates/volparossa/src/compute/private_conversation/WIRE.md).

### Bounded QEMU shutdown integrated

The shared VM wrapper now limits its poweroff SSH command to 15 seconds with a
10-second forced-stop allowance. Its normal shutdown and EXIT trap share one
idempotent routine: confirm exit, or allow 30 seconds for normal shutdown before
five seconds each for TERM and KILL. Abort skips the initial grace period. An
outer helper deadline bounds the entire observation; the trap cannot restart a
failed attempt with a fresh budget.

A Linux pidfd tracks the process being stopped; signals never use a numerical
PID fallback. The helper checks the original child parent and start time around
opening that descriptor. Initial binding allows at most two seconds for the
fixed QEMU launch command to appear, without following a changed identity.
Only confirmed termination permits shell reaping and scratch removal. Otherwise
private scratch remains, cleanup is unconfirmed and a successful guest result
becomes failure; an existing guest failure is preserved. This follows the
[Linux pidfd exit and polling semantics](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

All 25 focused tests pass, including real harmless child processes, delayed
exec, identity changes, TERM/KILL and the actual shell/helper/reap boundary.
Before integration with the Storage candidate, four existing VM-diagnostic
tests, shell syntax and scoped ShellCheck also pass; the focused suites pass
an independent rerun. The merged candidate's checks and remaining shell
diagnostics are reported in the Storage source checkpoint above. Quality runs the new checks before
the Rust build, and the existing non-mutating VM contract includes them. No
QEMU or model is launched by these checks. Full Quality `38708178755` and CodeQL
`38708173947` pass on the exact candidate tree. PR255 is merged into main as
`2491b8ca`. A subsequent actual Storage VM cleanup proof remains necessary; this does not
repair or explain Cloud's APPEND failure.

Earlier 15 October checkpoints remain retained: Android
[`38684878727`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38684878727)
preceded the two reproduced prepared/config byte-comparison corrections;
Code [`38681471469`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38681471469)
already showed one completed read and six memory-admission refusals before the
cache-advice candidate. Their original records remain in the
[earlier ledger](https://github.com/VOLPAROSSA/volparossa/blob/75da4143e06b220c68c3b32d6e9929bba3ad5d48/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence--15-october).
Storage run `38682910244` on `db50e01f` preceded the APPEND failure: its Cloud
RESERVE operations failed at TLS handshake and flow acquisition, and an exporter
bug hid provider activity. The correction `b7e63589` and original evidence remain
in the [pre-correction ledger](https://github.com/VOLPAROSSA/volparossa/blob/8967006e5dfc15de72bc80d5ac11de6f232d0961/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence--15-october).
Android
[`38674805209`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38674805209)
stopped at refresh observation (`observation_deadline`); Code
[`38675278393`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38675278393)
completed one read without identifying the six execution failures. Weather PR24
and core task diagnostics made the later observations above possible; they do
not by themselves establish either complete use case.

### Earlier integration evidence — 14 October

These earlier results remain historical evidence. They are not current running
trials or substitutes for the later completed outcomes above.

- **Android core delivery remains open.** On `ca292e41`, actual run
  [`38624043886`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38624043886)
  fails before starting the owner driver, tunnel or native Android process.
  The pre-QEMU KVM probe succeeds; about 40.6 seconds later the owner probe
  reports no read/write access and `EACCES` on the same fixed device path.
  The receipt's identity/device comparisons are against its newly captured
  owner baseline, not against the earlier preflight. They do not establish
  continuity across that interval. Owner/VM cleanup and exact ACL restoration
  pass; the cause of the access change is not yet established. Artifact
  `11923868858` ZIP SHA-256 is
  `48c74caa8c3402c440989a7c3cbad354602e6ee34e4af7612349adee0e6aeb98`.
  Quality `38624052635` and CodeQL `38624048007` pass on that source. Software
  checks do not turn this failed actual delivery trial into acceptance.
- **Storage consumer maintenance remains open.** Actual run
  [`38611919770`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38611919770)
  on `cdfa671a` fails Cloud publication at fragment 0, copy 0, `reserve`, before
  local READY: `CONTENT_UNAVAILABLE`, `stream_open`, enclosing deadline `none`.
  This does not identify the inner transport failure or rule out its own
  deadlines. The separate base restart/repair/two-restore/delete scenario
  passes; consumer repair, restore and remote cleanup do not. The cleanup
  receipt explicitly leaves remote cleanup and provider usage unproven.
  Artifact `11921330521` ZIP SHA-256 is
  `65fff550493741c7f9aec53cf3675535c262d28a64848ace376a97fc1f39e950`.
  Quality `38611450851` passes. Closed stream-open classification is the next
  diagnostic step, not an already demonstrated fix.
- **Cloud upload proof still depends on storage.** Quality
  [`38617137672`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38617137672)
  passes on `c550e5e8`, including the corrected static workflow assertion.
  This run does not execute the Cloud-specific 78-case Python suite or the
  actual upload-to-maintenance trial. PR234 remains separate from successful
  local SDK/component evidence and awaits the shared consumer proof.
- **The quote-only software slice is integrated.** PR247 is merged as
  `17afa3f0`. On `09b0d3cc`, targeted run `38512217556` passes 52 appraisal,
  16 guest and 12 quote tests; Quality `38512223814` also passes the eight new
  agent/control/CLI cases, and CodeQL `38512218075` passes. These remain
  software/synthetic checks, not real confidential hardware, a production
  quote route, full appraisal, worker admission or private-input release.
  [PR247](https://github.com/VOLPAROSSA/volparossa/pull/247) retains the original
  artifact hashes and failed attempts alongside current-source acceptance.

### Storage directory lock lifetime

Private archive, replica-set and fragment-set operations now release their
directory lock explicitly when the owning scope ends. Closing a plain file
descriptor could leave the lock held by a duplicate, including a descriptor
inherited before a child executes. The guard preserves exclusive access while
the operation is active, owner-only directory checks and anchored file access.

[Targeted trial `38696828273`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38696828273)
compares unchanged locking plus regression tests (`dd590d1a`) with the corrected
implementation (`788c11c4`). The identical three tests give one pass and the two
expected lock-retention failures on the baseline, then three passes on the
candidate. The existing uniform-storage lifecycle also passes, including legacy
three-copy handling and actual charges. Formatting passes. Original artifact
ZIP SHA-256:
`7ff7a66f555dc6eb376661dc6f4107d128d072e26a283b19a5a5768575c6af3c`.

This establishes the shared-descriptor lifetime correction, not the cause of
the earlier native-core [Quality failure `38688104130`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38688104130)
or distributed consumer acceptance. [Quality `38697903143`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38697903143)
passes on the exact reviewed tree, including all three regressions and the legacy
lifecycle in the full workspace suite, formatting, dependency checks and strict
Clippy. CodeQL also passes; PR254 is merged. Seven intentionally ignored tests,
three namespace checks skipped before entry and one optional harness skip are
not live datapath evidence. Original Quality log ZIP SHA-256:
`b60f561852fad9fcb6bd13ac9d0692718ac042e26060f8d9f855ec572fa91f54`.
The first [targeted attempt `38695362871`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38695362871)
stopped at incorrect temporary-directory permissions and formatting; the
successful comparison corrects those test fixtures without relaxing production
checks.

### TCP streaming under simultaneous backpressure

The proxy now polls both forwarding directions independently. A blocked request
write no longer prevents reading a response that the destination must finish
before it can read more request bytes. Both copy futures remain owned by the
proxy; cancellation drops both without leaving detached tasks or byte queues.
The two fixed buffers, directional byte limits, TLS flushing, half-close and
independent write/flush/shutdown deadlines remain unchanged. Progress in either
direction resets the shared read-idle timer, but cannot extend a blocked write.

Eight new regressions bring the focused streaming suite to twelve cases. They
cover simultaneous backpressure, real nested TLS, half-close, cancellation,
read-idle and blocked-write bounds, reverse-only progress and the reverse byte
limit. [PR252](https://github.com/VOLPAROSSA/volparossa/pull/252) integrates the
correction in main as `87f8c31d`. Its
[Quality `38663438337`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38663438337)
passes on `3cfbaba1`, including the twelve focused streaming tests; CodeQL also
passes. The change preserves the resolver backport, locked dependency graphs
and prior checks.

This fixes a reproducible streaming defect, not a proven cause of the earlier
Storage challenge timeout. The later actual storage failure above already
contains the corrected streaming code. Neither the in-memory tests nor this
transport correction establishes consumer repair, restore or remote cleanup.
The independent OpenCloud upload trial still waits for that shared integration.

### Integrated Hickory resolver security backport

PR250, merged as `4658ad3f`, backports the upstream DNSSEC-bogus answer
check to the Rust-1.85-compatible `hickory-resolver 0.25.2`. It rejects bogus
answers before cache insertion or alias following when resolver validation is
enabled. The root and fuzz graphs retain the existing API/version and use the
same reviewed path source. Production DNS settings, relay routing, trust anchors
and the separate shared-DNS `Proof::Secure` requirement are unchanged.

The second CNAME advisory concerns recursive resolution. Source review locates
the fixed code in the separate 0.25 recursor, absent from both locked graphs;
the stub's matching-answer chain receives focused regression coverage and a
graph-scope guard. This is not an unrestricted exemption for Hickory 0.25.
Archive, patch, reconstructed tree and unchanged license checks bind the exact
candidate; package notice collection includes the new path. Neither advisory
is dismissed or hidden by a new scanner exception.

Hosted Quality
[`38624534062`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38624534062)
passes on exact candidate `6e2ec216`. Its actual merge checkout `8a2f58c8` has
the same tree, `6bdf0ba1b93c95020fbac743b46485596c8895e5`. All **15 isolated Rust
regressions**, including the ten resolver cases, execute and pass. Locked
fetching, graph/feature guards, dependency/license and packaging checks, strict
Clippy, workspace tests and inert integration checks pass. CodeQL `38624530237`
passes all four analyses on the same head. Original Quality logs ZIP SHA-256 is
`4812656b0be7cb11330adb7946ac97b151692d235a53a61b59834b04c4ac41ad`.

Three namespace checks skip under the runner's user-namespace policy; no new
live datapath claim follows. Injected resolver verdicts are not a cryptographic
end-to-end DNS test. The existing `RUSTSEC-2024-0436` unmaintained warning remains
visible. Independent final source and original-log review found no merge blocker.

Before hosted execution, local source-only
verification reconstructs all four vendor trees exactly and verifies all license
and harness hashes. Shell syntax, ShellCheck, the four existing inert SEV license
fixtures and focused resolver notice collection pass. Independent source review
checks the ten new resolver cases and the manually extended standalone lock;
this is not Cargo resolution or executed Rust evidence. The concurrent
storage and Android actual trials keep their original source revisions and
remain independent of this candidate. See the
[reviewed dependency sources](../third_party/rust/README.md#resolver-validation-and-cname-scope)
for upstream fixes and the precise reachability assessment.

#### Retained failed attempts and lock correction

The first [hosted Quality run `38619532866`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38619532866)
on `a61465b1` stops at the isolated harness's locked dependency fetch. Root and
fuzz locked fetches succeed; Cargo requires a harness lock update. PR merge
`b3806ae8` has the exact candidate tree. Formatting and shell checks pass, but
resolver compilation, regression execution and full dependency/license checks
have not run. Original logs ZIP SHA-256 is
`096d1f762f007784b5f23cfc9363b636d75924a93cef3af28495c20d2940265c`.
Reconcile that standalone lock with Cargo on the disposable hosted runner,
retain the original and generated lock difference, and keep the locked gate
failing until the reviewed correction is committed. Do not infer a valid lock
from a manually complete-looking dependency graph.

The failure-only diagnostic copies the authenticated standalone harness and its
four reviewed vendor trees to temporary runner storage, then asks the already
installed Cargo 1.85 to reconcile that lock offline without building. It exports
only the before/after public locks, their diff and a closed status. Root, fuzz
and original harness locks stay unchanged, and the original locked-fetch exit
still fails Quality. A generated lock is evidence to review, not an automatic
correction or a passed regression suite.

[Run `38622766542`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38622766542)
on `33ff90c3` preserves the original locked-fetch failure and successfully
reconciles the isolated lock with Cargo 1.85 offline. The exact generated diff
adds only `uuid 1.24.0` edges to the already-present `js-sys` and `wasm-bindgen`
nodes. No registry version or checksum changes; all three original locks remain
unchanged in that run. Artifact `11923890129` ZIP SHA-256 is
`a252d588381aa94d8cd7ad773843406af0248f173278883f6345330b3be645b4`.
The two-line correction is now applied byte-for-byte; the standalone lock hash
and its three provenance references are updated to
`965c606acf0c93d9a9d6b8415b3ae503185e8b3ec7eecf3d6251c9047cd14659`.
That correction alone did not prove resolver execution. The subsequent hosted
acceptance above supplies the previously missing locked-fetch and Rust results.

### Retained storage-branch evidence — earlier checkpoints

The following source-specific results preceded the current APPEND diagnostic
candidate. References to next steps and pending checks describe those checkpoints,
not the current execution plan. The current table and checkpoint above take
precedence; completed tests and original failures remain retained below.

#### Earlier storage validation and consumer challenge failure

[Quality `38669294423`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38669294423)
passes on `f94c4c74fb66ce4e781d36a26a8a41f2f8986167`: formatting, strict
Clippy and 3,803 unique workspace tests pass, with zero failures and seven
ignores. This includes the new signed pending-handoff retention regression.
The focused streaming suite passes all twelve tests; isolated agent-outcome and
wire suites pass seven and 28. Three namespace proofs and one optional CLI
fixture skip; those skips do not establish actual network behavior.

The original Quality checkout is merge `4846122f`, combining main `87f8c31d`
with that head. All crate source and test files match the candidate; the complete
checkout is not the branch-head tree. Original log ZIP SHA-256:
`a95277245cd11f130df28706d355ea5f18d42e1b26797fb18d6ae9983eb7a159`.

Actual [run `38667836184`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38667836184)
tests exact `9127a8fcd83ea440ca0e366c2cb1ae378f857ab1`, with unchanged consumer
profile 7. Its separate base evidence validates core restart, fresh owner-turn
reconciliation, pause/resume, provider withdrawal, two verified restores and
deletion of all eleven retained copies plus the foreground archive. The three
base provider stores finish with zero usage. This run therefore passes the
baseline that stopped the earlier `38662571845` trial; it does not establish why
that earlier run failed.

The later Cloud publication fails on fragment 0, copy 0, while preparing
`finalize`. The original consumer node version 8, observation version 7 and CLI
diagnostics version 6 agree: `CONTENT_UNAVAILABLE` at `agent_ready`, challenge
phase `challenge_read_verify`, deadline scope `operation`, less than one second
before the challenge exchange and 90–120 seconds inside it. Selector and grant
writes/flushes have completed locally, but no verified challenge reaches the
client. The signed finalize request and provider-side finalize backend work
come after that boundary. Local flush completion does not prove provider
receipt, and the provider event snapshot cannot correlate a cause to this
request. The original 120-second operation budget is unchanged.

The streaming source already matches the PR252 correction merged in main
`87f8c31d`; this failure is not evidence that the fix is missing. The next
unresolved boundary is provider grant/challenge progress for the failed
exchange, not baseline custody reconciliation. No deadline extension or retry
is justified by this receipt alone.

The combined report remains failed at `storage-consumer-publish`, with
`CONSUMER_APPLICATION_FAILED` and null combined maintenance/consumer evidence.
The consumer Node process is joined, local fixtures are removed and no owned
fixture processes remain observable; consumer provider usage and remote
deletion are not confirmed. Base private cleanup completes; the disposable
guest has zero remaining owned network
objects and byte-identical root network state before and after. Consumer
maintenance/restoration and Cloud PR234's separate actual trial remain gated
on shared acceptance.

The original artifact contains 76 files. ZIP SHA-256:
`ba75d48332b5232ccdd5277d7090852b1d7202e14f5f38bd1ff8afe92f97117a`;
log ZIP SHA-256:
`2f646356c8fd0a3468cd5f220f7857a7152239456fd92a0caefc5d6048c391e1`.

#### Earlier receiving-provider activity preparation

The next diagnostic observes the receiving side while the exchange is still
active. Four fixed process-local slots report only aggregate protocol phases,
coarse time spent in the current phase and counts. Session cancellation releases
its slot even before the task's first poll. The independent snapshot does not
wait for publication, disk or service locks; an inconsistent observation is
explicitly unavailable. Request-read is reported only after the existing signed
challenge write and flush have returned, not as proof of client receipt.

`content provider-activity` uses the existing protected local operator socket.
Its additive control tags and version-1 payload do not change storage frames,
authorization, retries or the four-session and existing timeout limits. No peer,
request, archive or account identity appears in its JSON.

The current consumer trial samples only its three provider operator sockets,
at most one round per five seconds and for at most 512 rounds. Each CLI query is
bounded and joined. An optional, at-most-8-KiB sidecar retains the latest snapshot
and longest observed wait per provider role before cleanup removes active
connections. A failed observation never replaces the application's result or
counts as custody, cleanup or causal evidence. Historical consumer profiles and
acceptance receipts retain their existing contracts.

Independent Rust and Python/shell source review is complete. The 190 targeted
inert Python checks pass, including cancellation, finite/private output,
historical orchestration, helper staging and projection before an application
failure. Review corrections make uncertain query cleanup explicitly unconfirmed
and prioritize this small sidecar within the unchanged emergency-export budget.
Eighteen new Rust tests cover the slot lifecycle, signed challenge flush, closed
wire domains and real Unix control/CLI binding; their hosted compilation and
execution remain pending. No new actual storage trial has been started.

#### Storage challenge progress and earlier hosted evidence

PR232 now adds request-local progress within the provider challenge exchange:
selector write/flush, grant write/flush and challenge read/verification. Coarse
elapsed-time categories distinguish budget spent before that exchange from time
spent inside it. The operation start is the same instant used to construct its
original deadline; failure freezes the observation, while success, cancellation
and movement to another boundary clear it. No exact timestamps, identifiers,
payloads or raw errors are exported.

The optional local-control message is restricted to a matching pre-READY
`CONTENT_UNAVAILABLE` rejection at the challenge boundary. CLI JSON version 6
adds the nullable `challenge` field; versions 1–5 keep their exact shapes.
Image `43029ea8` and Cloud `e0db1cac` accept this bounded contract. Consumer
profile 7 pins their exact files and selects consumer evidence version 7 and
combined report version 6 explicitly; historical pins and reports stay intact.
Pin manifest SHA-256:
`714600367409bae562b3bdd63c474a0f40629b5882e6f6370b85f951acb58a15`.

All 224 targeted core harness/validator checks pass, as do 57 Image and thirteen
Cloud adapter checks. Bash syntax, ShellCheck and independent source/provenance
review pass. Historical adapter comparisons preserve version-1–5 acceptance and
serialization across 47,280 inputs. Nineteen new Rust tests cover progress,
original deadlines, cancellation, wire compatibility and correlated CLI output;
the following hosted Quality run executes all nineteen successfully. The diagnostics do not
change I/O, authorization, retries, time limits, custody or cleanup. They are
not yet evidence of a transport fix or successful consumer restoration.

The first hosted Quality run, [`38652893003`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38652893003),
stops at three Rust formatting differences before compilation or Rust tests.
The three whitespace-only corrections are applied. Its checkout `67dc79cb` combines main `7b728846` with candidate
`f6a83924`; all three affected source files match the candidate exactly.
Original log ZIP SHA-256:
`3c4a132aca7bded0a6cd8b950de877c39f2b844e26e377e9a05ca03c8dfd1eaa`.

[Quality `38653565238`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38653565238)
passes formatting, strict Clippy, workspace tests, the nineteen new Rust tests,
and isolated agent/wire suites of seven and 28 tests. Three namespace proofs,
seven workspace ignores and one CLI fixture skip remain non-acceptance.
Checkout `75274332` combines main `7b728846` with `7b27d13d`; audited branch
source files match the head, while root manifests/locks match main. Original
log ZIP SHA-256:
`e380460a322e1846592a8ec38afcf8ee1d3c1c5407457cbd60eb6de9bda6b361`.

Actual [run `38653857407`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38653857407)
checks exact `7b27d13d63ed8e15bdf3dfc55f14444102f2f35c`. The separate base
maintenance proof passes restart/resume, withdrawal, repeated restores and
deletion of all eleven copies plus the foreground archive, ending with zero
provider usage. The later Cloud publication fails on fragment 0, copy 1, while
preparing a finalize operation. No READY challenge arrives, so the signed
finalize request has not been sent to the provider.

The original diagnostic records `challenge_read_verify`, less than one second
before the challenge exchange and 90–120 seconds inside it, ending at the
unchanged operation deadline. Successful local selector/grant flushes do not
prove provider receipt. Uncorrelated provider events cannot identify the failed
request or establish a transport cause. The combined consumer proof stops before
maintenance and restoration, and does not confirm remote cleanup or provider
usage. Local fixture cleanup completes; no owned network objects remain and
the guest root network state is byte-identical before and after the trial.

The original artifact contains 76 files. ZIP SHA-256:
`84ad2a9c657cc03f23b73959e8b0c33c669984b20e54e3eab94f53ab31d27566`;
log ZIP SHA-256:
`c1cd237e469eb2fc1ff28a075c93eb6798ef087ee795ef54d8f627c91a16a374`.
Cloud PR234's exact-source Quality `38656306237` also passes, but its actual
upload-to-repair trial remains gated on successful shared consumer maintenance.

#### Earlier storage-branch streaming correction

Source review finds a separate forwarding defect: awaiting an entire write and
flush inside one selected read branch prevents the reverse direction from being
polled. Two bounded peers writing before they read can therefore stall each
other. Existing request-then-reply tests do not exercise this sequence. The
original Storage receipt does not prove that this caused its challenge timeout.

The correction polls two owned directional futures concurrently, with the same
two bounded buffers, directional byte limits, shared read-idle observation and
individually bounded write/flush/shutdown operations. It preserves half-close
and drops both directions on error or cancellation; it spawns no detached task.
Eight new regressions bring the streaming suite to twelve tests, covering
simultaneous backpressure, nested real TLS, cancellation, half-close, byte limits
and timer behavior. Quality now runs this focused suite before building the
dependency-audit tools, without removing any later gates. A component result
will not by itself establish genuine MPTCP, provider authorization or a
successful shared Storage/Cloud trial.

The first [Quality run `38661475337`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38661475337)
on `71aab29d` stops at one test-formatting difference, before Rust compilation or
test execution. The exact whitespace correction is applied; no behavior changes.
Its original checkout `210a3d22` combines main `7b728846` with that head.
Original logs ZIP SHA-256:
`9e765901d287d4c966a70541a8258fb0ea2903e95ddbad352c4b3414f42cdb3b`.
[Quality `38661788072`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38661788072)
on `ea6efddb` passes all twelve streaming tests, nineteen request-progress tests,
isolated outcome/wire suites of seven and 28 tests, and 3,802 workspace tests
with zero failures and seven ignores. Checkout `7800d9e3` merges main `7b728846`
with that head; all 41 changed code/test/harness blobs match. Three namespace
proofs and one optional CLI fixture skip. Original log ZIP SHA-256:
`ae02a10b5bcf8bd6103b16eccd7cbbb4ede29620b3dd9df55a3e61fb93d36e60`.

The isolated four-file streaming fix is now merged through
[PR252](https://github.com/VOLPAROSSA/volparossa/pull/252), main `87f8c31d`.
Its own Quality `38663438337` passes all twelve streaming tests and 3,663
workspace tests; CodeQL `38663436370` passes all four languages. The complete
tested tree matches the isolated head `3cfbaba1`. This does not accept the
larger Storage integration or attribute its failures to that defect.

#### Earlier restart reconciliation failure and retention regression

Actual [run `38662571845`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38662571845)
uses exact `ea6efddb0a7b6d9039b368c89a8b8fb8a7d3b7ae` and unchanged consumer
profile 7. It fails earlier than the previous consumer upload, during
`private-storage-maintenance-core-restart`: `baseline_custody` at
`reconcile_progress`. Base maintenance and consumer results are null. Initial
upload evidence validates 74 completed protected MPTCP/TLS flows, zero recorded
failures and two relays; that does not establish later reconciliation.

The failure record's five committed, three uncertain and one unattempted copy
are the earlier **core-loss snapshot**, not the failed final progress. Its
cursor 5 / paused likewise predates the fresh owner process; source ordering
establishes that turn 6 completed before the baseline check. The final progress
and fresh-turn outcome were not exported, so neither data loss nor a particular
pending-handoff, expiry or accounting failure is established.

One completed bounded maintenance turn may legitimately retain a pending
handoff. Foreground progress observes/reconciles existing custody but does not
itself finish an unattempted replacement upload. The baseline therefore remains
strict: a completed turn is not sufficient evidence of completed recovery.
The failure-only v3 candidate separates the already available final progress
and fresh-turn observations from earlier snapshots, with closed reasons for the
failing guard and an 8 KiB maximum. It adds no operations, retries, deadline
extensions or weaker acceptance; success evidence is unchanged. All 76 smoke
and 41 wiring tests pass locally, including eight new diagnostic cases and a
differential comparison against the original custody predicates. Independent
source review passes. The original v2 failure record still validates unchanged;
v1/v2 keep their exact historical field sets. These inert checks do not establish
the actual failure's cause or successful distributed recovery.

The later actual run `38667836184` passes this baseline and stops at the
consumer challenge boundary described above. A separate regression exercises
a real signed pending handoff using local provider stores: source renewal outlives the original
target lease, two maintenance scans must retain the source, and the next selected
fragment rotation must renew the target before retirement. It preserves the
original manifest and signed placement. Independent source review passes;
Quality `38669294423` compiles and executes the regression successfully. This
component result does not explain the earlier actual failure or independently
prove the daemon's complete restart lifecycle.
Quality `38668784174` on `2ce60073` stopped at formatting, before Rust compilation
or execution. Its three formatter changes are applied without changing the test
semantics; the later Quality result validates them.

For the earlier `38662571845` failure, the original lifecycle, route,
provider-event, supervisor and control-transition diagnostics validate.
Provider snapshots cover their baselines without recorded
storage failure tuples; client/control rings do not, so absence there proves
nothing about this failure. Local cleanup completes with zero owned objects;
guest-root host-state hashes match. Final deletion and zero provider usage are
not proven by that earlier trial. Cloud's separate actual trial remains gated
on shared acceptance.
Original artifact ZIP SHA-256:
`10ffd422e4e9da4ea3f99f4356bfcb2ccdcfa6a2291318e791a813971aa725c6`;
log ZIP SHA-256:
`9fa16d3435d867a43b6e39b0858fea28fe26e88da1a41b45267895415ec6c025`.

#### Earlier protected storage stream diagnostics

The preceding PR232 candidate adds a request-local, finite failure classification for
the protected stream before the provider TLS handshake. It distinguishes policy,
route state/material, flow acquisition, transport certificate/TLS, initial paths,
OPEN_TCP writing, subflow readiness and stream attachment. This is diagnostic
evidence, not a transport fix or a remote acceptance receipt. It does not change
the existing eight acquisition attempts, deadlines, routing, authorization,
storage accounting or cleanup.

The additive local-control field is projected only for a matching pre-READY
`CONTENT_UNAVAILABLE` rejection. Success, cancellation and enclosing timeouts
clear the observation. CLI diagnostics use version 5; versions 1–4 retain their
original closed JSON shapes. Image `949f208d` and Cloud `7d10c494` accept the same
bounded contract. Consumer profile 6 pins those exact Git objects, with a version-6
consumer report and an explicitly selected version-5 combined report. Historical
reports are not upgraded into new evidence.

Targeted inert checks pass: 217 core harness/validator cases, 55 Image adapter cases
and eleven Cloud cases. Independent source review and 26,656 in-memory historical
adapter comparisons find no changed version-1–4 acceptance or output. Hosted
Quality `38644244295` now passes all seventeen new or extended Rust cases and the
corrected version-5 assertion, plus seven isolated agent-outcome and 25 isolated
content-wire cases. Strict Clippy, workspace tests, dependency/license checks and
the inert harness pass. Three namespace-backed proofs explicitly skip under the
runner's user-namespace policy.
No private payloads, paths, identities or raw errors are added to exported evidence.

That Quality run checks merge `abddfe76`, combining main `7b728846` with
`1cdc6272`. The 21 audited implementation, crate-manifest and toolchain files
match the head; root Cargo files match main, and the workflow combines main with
the head's two isolated-storage steps. The whole checkout is not the branch-head
tree. Original log ZIP SHA-256:
`84ad75c6af7ab8b16af71e921ae6faf3b85aeaf00ac41c6392643889d333e9f2`.

The first hosted [Quality check `38635879441`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38635879441)
on `9eb00b2b` stops at Rust formatting, before compilation or Rust test execution.
The nine indicated formatting changes in five source files are applied without
behavior changes; fresh hosted validation remains required. The original log ZIP
is retained with SHA-256
`5b13d2fe1f380b88d242d01a961563d65b7d0e1c89ec1977445a0f4632afc208`.

Follow-up Quality `38636353400` on `ae592cfb` passes formatting, dependency
checks and standalone fuzz lint, then stops at one `doc_markdown` lint: the
`OPEN_TCP` identifier in a source comment needs backticks. The comment is corrected
without executable changes. Workspace and targeted Rust tests have not yet run
for this candidate. Original log ZIP SHA-256:
`e4077a60a4fcbeef61d7cb22c267edec2c20d9ae26e45a17c6f8b3436de4d99a`.

Quality [`38638283974`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38638283974)
on `473a0da6` passes formatting, dependency checks and standalone fuzz lint, then
stops at four strict Clippy findings. Two require appropriate value/reference
passing; the other two are function-length limits. The correction borrows the
activation failure, copies the two-byte diagnostic value and moves the unchanged
JSON scope checks into a helper. A documented, function-local length allowance
keeps the ordered stream handshake, transfer and cleanup in one ownership scope.
No deadline, acceptance rule or error mapping changes. Workspace and targeted
Rust tests were skipped, so compilation and execution still require fresh hosted
validation before an actual storage trial. Original log ZIP SHA-256:
`afc0d769391add76f4492cab4218165dd5bff5ed1d181e86ed76e055bbc7452e`.

Quality [`38640886944`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38640886944)
on `b996160c` passes strict Clippy, then fails one CLI assertion: the live
diagnostic projection emits version 5, but its expected outcome fixture still
uses historical version 4. The CLI binary reports 641 passed and one failed.
All three new version-5 CLI cases and the correlated-detail case pass; the other
thirteen new agent/control cases and later isolated-test gates do not execute.
The correction changes only that live-projection test's expected version and
name. The historical version-4 fixture and its exact roundtrip/rejection tests
stay unchanged. Production source, deadlines and acceptance rules are untouched.
The subsequent Quality result above verifies the corrected assertion.

The original checkout is PR merge `526a1968`, combining `b996160c` with main
`7b728846`; evidence is bound to that checkout rather than claiming an exact
head-tree match. Original logs ZIP SHA-256:
`bfa4871c0f9724393350dade2bbedff97a4cf250334007b3cebd8f21265fb580`.
The separate actual trial retained its original revision; the test-expectation
correction did not restart or reinterpret that trial.

#### Earlier storage trial

[Run `38643001237`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38643001237),
job `116122914558`, checks exact source `b996160c`, not a PR merge. The combined
trial fails during **Image publication**, before reaching Cloud: fragment 0,
copy 1, `append` returns pre-READY `CONTENT_UNAVAILABLE` with stage `challenge`
and deadline scope `operation`. Transport opening and provider TLS have already
completed. The request's 120-second overall budget also includes admission,
route preparation and provider lookup; this result does not prove that the
challenge itself consumed 120 seconds. The current records do not identify
whether selector writing, grant writing or challenge reading was pending.

The separate base records pass their original validator: four fragments with
two copies each, owner renewal, core restart, SIGTERM/resume, provider-withdrawal
repair, two non-consuming hash-verified restores and deletion of eleven retained
copies. All three base stores finish at zero usage. The combined report remains
failed, with no accepted consumer lifecycle or restore.

Owned namespaces and local private fixtures are removed. Guest-root network
snapshots remain identical at
`f0d2002111a7196647d01bb474f222680393f56d08becd4c733bc3c33c3bdded`.
Consumer cleanup explicitly leaves remote cleanup and provider usage unproven;
the base stores' earlier zero usage cannot establish either. The client event
ring is full and does not cover the whole publication interval, so its absence
of particular events cannot identify the failed operation's cause.

Artifact `11933303536` contains 76 original files, ZIP SHA-256
`2e82ad9614843e20ac91748b01992dfce2f544857fa3e8953df5ead4e2e78b9d`;
original log ZIP SHA-256
`eda95612949cd1c1fe301ca95baf6120e3dad0c9acc40694719f302e736068d9`.
Source and closed-report review establish the timeout boundary, not its
underlying cause or a fix for the earlier stream-open/receipt failures. The next
step is to distinguish budget spent before the challenge from progress within
that exchange, without increasing deadlines or adding blind retries.

#### Earlier storage stream-open failure

[Run `38611919770`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38611919770),
job `116017175277`, checks exact source
`cdfa671aee09479e16958239848e2bbd0639bb6f`. All thirteen owner, seven isolated
agent and 25 isolated content-wire prerequisite tests pass. The real topology
then completes the base archive's renewal, core restart, SIGTERM/resume,
provider-withdrawal repair and two non-consuming, hash-verified restores. The
base finish deletes eleven retained copies and independently reports zero usage
at all three stores.

The combined application continuation fails at `storage-consumer-publish`.
Cloud's first reserve, fragment 0/copy 0, returns `CONTENT_UNAVAILABLE` at
`agent_ready`, with `stream_open`, no recorded deadline expiry and no TLS failure
classification. Provider lookup/cardinality and offer-validity checks have
already passed; the provider's TLS handshake and storage request have not
started. That revision's `open_content_stream` collapses policy, transport acquisition
and MPTCP/TLS activation failures into that same result, so the underlying cause
is not yet established. This differs from the earlier FINALIZE `wire_receipt/io`
failure and does not prove that earlier defect fixed.

The original schema-4 report remains failed. Consumer repair, cold restoration
and provider-zero cleanup have no completed combined receipt. Local private
fixtures and owned namespaces are removed, and guest-root host snapshots match
at `2cc2418089a5866d37b45112dc98fd6e9dc7434d70733a275ec53e1f440a182c`.
Base zero usage must not be reused as proof of subsequent consumer cleanup.
The bounded client event ring does not cover the whole publication interval;
missing event categories cannot prove absence or attribute the failed request.

Artifact `11921330521` retains 76 files. Its original ZIP SHA-256 is
`65fff550493741c7f9aec53cf3675535c262d28a64848ace376a97fc1f39e950`;
the original log ZIP is
`bbd152e4a335dd4331081ccf82c7fbcef3f0ca4f1ec593369d33c2a4e5137013`.
Independent readback verifies the exact source, failure and limited evidence.
Separate Quality `38611450851` succeeds on merge `dd45c334`; only README differs
from the candidate, so tested code/workflow bytes match. Its namespace skips
do not substitute for the actual failed consumer result.

#### Earlier isolated-test build gap

[Run `38607252325`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38607252325),
job `116001235165`, binds exact source
`d22f7892c76020a3addaf360a3b01507ff7164fd`. Its disposable guest passes all thirteen
owner-maintenance tests and seven agent-maintenance tests, then exits 101 in
`storage-maintenance-targeted-tests`, before topology setup. The separate
`volparossa-content` library build reports two `E0599` errors for `start_paused`
in `private_storage/wire/tests/bridge_observation.rs`: its own test dependencies
do not enable Tokio's `test-util` feature. The content crate now declares that
feature only under development dependencies, and Quality runs its storage wire
tests without unrelated workspace feature unification. The later Quality and
actual prerequisite results above verify this correction; production dependencies
and deadlines are unchanged.

The earlier agent build gap in
[run `38595365736`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38595365736)
is separately resolved: Quality
[`38601264906`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38601264906)
passes on the same `d22f7892` source and actually executes all seven isolated
agent outcome tests. Neither this component result nor the successful guest
prerequisite tests establishes storage custody or distributed recovery.

Artifact `11916904333` from run `38607252325` is retained with original ZIP SHA-256
`44a0996dab5eae2fe1dd2a3ecc768603395c4fdd15539cf0c07d13bad1da6cca`, matching GitHub's
artifact digest. Its incomplete report records `success: false`,
`topology_phase: null`, unverified cleanup and unverified host state; the seven
retained files contain no completed topology or consumer receipt. Provisioning
of the pinned Image/Cloud adapters succeeds, but does not prove application
restoration or peer storage.

This run provides no new evidence about the earlier Cloud FINALIZE
`wire_receipt/io` failure in run `38519187504`. Profile 5, the original consumer
operations and their acceptance criteria remain unchanged. Consumer repair,
restoration and remote cleanup are not yet proved.

<a id="authorized-quote-exchange-candidate"></a>

### Authorized quote exchange and authenticated refusal

#### Integrated signed device refusal

PR258 is integrated as `71209145` after full source checks and the actual
production-route refusal trial pass. See the
[latest completed evidence](#latest-completed-integration-evidence--15-october)
for the final result and its boundaries. The following checkpoints retain the
earlier source and fixture failures; they are not outstanding acceptance gates.

The follow-up preserves successful quote encoding and adds a separate,
request-bound provider claim: `fixed_quote_device_unavailable`. The provider may
send it only after authenticating the authorized requester, attempting collection
through the fixed guest device and rechecking cancellation, expiry and authority.
Other firmware errors, transport failures and authorization failures do not
become this claim. The requester checks its signature and original request
binding before the agent closes the exchange streams and rechecks policy.

The CLI exposes the refusal as a closed version-two result and exits
unsuccessfully. It rechecks the original challenge lifetime after the final
acknowledgement. Its result names the local agent as the signature verifier;
the CLI receives no portable signature proof and does not independently
authenticate that claim. Quote verification, appraisal, worker admission and
private-input release remain false. A provider signature authenticates the claim, not the
physical absence of hardware; an inaccessible device can also cause this refusal.
The existing version-one success result is unchanged. Older callers reject the
new refusal rather than treating it as evidence.

Targeted hosted source checks now pass in
[run 38740806726](https://github.com/VOLPAROSSA/volparossa/actions/runs/38740806726)
on `92271e9e`: 87 Python tests and 55 unique Rust tests across guest collection,
signed outcomes, pending-session completion, agent handoff and CLI results.
Formatting and strict Clippy for the three affected packages also pass. Original
logs confirm the exact checkout/tree and unchanged lockfile; their ZIP SHA-256 is
`e5eca7df32573713d3c04e5a376b786a4e77eaaab1ca638a2517323c503ddd43`.
Earlier runs `38737101441` (formatting), `38737643834` and `38739086162`
(Clippy) remain separate failed source checks, not successful acceptances.
The later full Quality run `38742834852` stops at the unchanged exact-source
advisory guard: the guest wrapper's reviewed cancellation/error ordering needs
its new hash. The guard is rebound to that exact wrapper after independent
source review; no RSA operation, dependency, feature or advisory scope is added.
All twelve inert source/metadata mutation tests pass locally. Full hosted
integration was still pending at that checkpoint; the targeted workflow was
extended to check this guard too.

These source checks alone did not prove a hardware report, protected task or
working route. The later actual supplies refusal-route evidence, not protected
task execution.

The new `protected-quote` topology scenario prepares that negative route trial:
wrong-requester rejection, an authenticated device-unavailable claim, and rejection
after the single authorized attempt. It uses the production provider path and
observes the fixed device's absence in the provider service's mount namespace;
it does not substitute firmware or admit private work. Fourteen inert checker
tests, eleven wiring tests and four existing VM-diagnostic tests pass locally.
Only a closed guest report and a separate original host-side VM-cleanup receipt
may be published. These tests validate the harness, not an executed topology;
actual route and cleanup acceptance were still pending at this checkpoint.

Full Quality run `38747335446` on `5f7e8f3a` stops in the historical Weather
export fixture: it invokes the extracted exporter under `set -u` without the
new scenario flag that the real runner initializes. The fixture now explicitly
selects `protected_quote=no`; its expected exports and failure assertions are
unchanged. A separate inert test checks that the quote scenario returns before
any general export. The failed run is not integration acceptance.

Quality run `38748458971` on `46564f39` passes that Weather step, then stops
in the Android VM-cleanup fixtures: four extracted-shell fixtures omit the
`scenario` initialized by the real runner. They now explicitly select
`content-provider`, with the original exit-status, join, private-state and
no-overwrite assertions unchanged. The targeted workflow also runs this
existing 18-test suite. This second fixture failure is retained separately
from the successful source-only run `38747325606`; neither proves a live route.

Quality run `38749561548` on `7fa4dee3` passes both corrected steps, then
finds the same missing `scenario` in the older QEMU lifecycle test's extracted
cleanup fixture. That fixture now explicitly selects `alpha`, without changing
its shutdown, status or scratch-retention assertions. The targeted workflow also
runs its 25 cases; no production shutdown path is changed by these corrections.

The first dispatched route trial, `38752117836` on `4a39e38f`, stops before
VM preparation in the cooperative-browser preflight test. Its extractor only
recognizes `if`, while the preceding quote-export branch makes the unchanged
cooperative selector an `elif`. The test now recognizes both branch forms and
executes the same four-cohort gate independently; `protected-quote` is also
explicitly rejected by that cooperative gate. The targeted workflow adds the
existing browser and Code VM-contract suites. No VM starts, no route or refusal
is observed, and no cleanup reports are produced by this failed run. Separately,
source-only run `38750363249` passes 190 Python cases, 55 unique Rust cases,
formatting and strict Clippy on the same commit.
The complete preflight's 99 Python invocations and 58 shell syntax checks now
exit successfully locally. Four Node-dependent cases also pass with the existing
verified runtime; the optional real CLI/GPG and three namespace cases stay skipped.

The replacement route trial, `38754172447` on `2dfe81e0`, passes that preflight
and starts the VM, but returns status 69 without a guest route report. Its only
published artifact is the independently validated host receipt confirming QEMU
termination/join and private VM-state removal. This is not guest-topology cleanup
or route acceptance. Source review finds a concrete mismatch: the quote driver
does not build the content/HTTPS transfer examples, while the shared provider
preflight requires both. Quote-only now skips those two executable checks and
their later staging calls; ordinary providers retain both. Executed inert
preflight and all-scenario build/staging regressions verify that distinction.
The original guest stderr was not exported, so this mismatch is not an observed
inner error message. The resulting 13 wiring cases pass locally; a corrected
actual trial was still pending at this checkpoint. Separately, source run
`38754168513` on the original commit passes 230 Python cases, 55 unique Rust cases,
formatting and strict Clippy.

#### Integrated quote exchange

The software slice is now integrated through
[PR247](https://github.com/VOLPAROSSA/volparossa/pull/247), merge `17afa3f0`.
Its tree `18eac7f7d42bc5f04ea83a70d2512946f30fa264` exactly matches tested source
`09b0d3cc349337e49ca48e23832f1b1db2d62f79`.
Original targeted run
[`38512217556`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38512217556)
passes 52 appraisal, 16 guest and twelve quote tests, plus targeted Clippy.
Quality `38512223814` passes strict workspace Clippy and 3,655 workspace tests,
with zero failures and seven ignored tests. All eight new agent/control/CLI
regressions actually execute and pass. Its three namespace wrappers cannot create
the required namespaces; they are not live datapath evidence. CodeQL
`38512218075` passes all four analyses and the aggregate check.

Independent reconstruction and root replay confirm the original artifacts and
logs, exact source/tree and unchanged committed lockfile. The core, guest and
quote artifact ZIPs for `38512217556` are respectively
`c66de783d3b42ba875ba1820bb4dafbfcb962dac277c0e3a64eefb62e5a9c026`,
`a679817b06a133a1b58c90bd51efcbda5ff90db2a9492c418e3a66432abdb71b`
and `b7dcd2dee7dc44e632bb98586de281fae519ee680f63605daee7b3f394ebb472`.
Its log ZIP is
`5992a88556979020e9f7e93f59e48f73cbff6408dc5af86ec3d94cc6dff83152`;
the Quality and CodeQL log ZIPs are respectively
`bd0d84401bd2021638c994d78cdf4a42fac42de448e58679dccb580bcafe56a0`
and `d0bb8688e008f17bea9a8ee381ae66562e39180c4f0528b29778d8563632aff9`.
Software integration does not establish confidential hardware or private-task
execution. The earlier revision-specific results remain below.

The new quote-only path connects guest-owned evidence collection to the existing
protected provider stream. An operator must explicitly authorize one requester
identity, a lifetime of at most ten minutes and at most 64 attempts. Registration
is independent of public compute. A separate operation selector and signing
domain prevent public-job messages from being treated as attestation requests.

The CLI creates its fresh, one-use challenge only after route setup, pinned TLS
and the provider's authenticated challenge have succeeded. It receives the bounded
binary quote on that same local control connection, completes transport and policy
checks, then applies the existing reference-evidence verifier. No raw report,
hardware identifier, key or transcript is printed or put in a public cache.
The result keeps full appraisal, worker admission and private-input release false.

The service owns retained keys and an expiry supervisor. Detach, authority loss
and expiry revoke the key without claiming that a blocking firmware ioctl has
stopped. One process-wide permit remains with the actual worker until it returns,
including across detach and reattach. This prevents cancelled requests from
creating an unbounded series of firmware workers.

Original hosted run
[`38511031734`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38511031734)
on `85a013825ce33e2122de344092d8a3889a4af2b5` passes all 52 appraisal tests,
16 guest tests and twelve quote tests, with zero failures or ignored tests.
Targeted content Clippy also passes. The separate quote receipt requires the
appraisal and guest results from that same source; all three stages actually
execute. Independent reconstruction and root replay confirm the original
artifacts, exact tree `4a64a68df7a3ba572a572d7b20336dccdc0666f1`, unchanged
committed lockfile and the digest chain between prerequisite receipts.

The original core, guest and quote artifact ZIPs are respectively
`e4e66a899b324c57e90c355f20f149c32c4549b249107c3768708ca501b18c04`,
`d48540551b72e3efb83aabd2653940be4c3c69dcbae3530f62a53a7b3427fcbc`
and `50bfd73b1cc61d13005145ad802e5c4afd6d8cc8ef65c3daaa81de9772e33eca`;
the original log ZIP is
`45d8e1dd32c49ac607e7682e53d4695624035f4ca33a0ef7c3eefbf4706c3001`.
These synthetic guest and quote reports do not prove firmware success, a working
production route, confidential hardware, full appraisal, worker admission or
private-task execution. See the
[quote exchange guide](development/PROTECTED_COMPUTE_VERIFIER.md#authorized-quote-exchange-candidate)
for commands and the remaining authority boundaries.

Original run
[`38510015317`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38510015317)
on `944da52cb9b5bbfed29f2f3e93b337f83b4b56f8` fails three Clippy rules:
`similar_names`, `map_unwrap_or` and `ignored_unit_patterns`. Its 52 exact
appraisal tests pass with zero failures or ignored tests. The guest and quote
steps are skipped; their artifacts contain only failed receipts, not executed
tests. Independent reconstruction and root replay confirm the exact source,
unchanged committed lock, original artifacts and this limited result. The core
artifact ZIP is
`6411652b4098e504bf50d8891be281401a4f2f24518944b76883705c9a5ac944`;
the original log ZIP is
`10bf16d005a56ef7de6b1b39a918506c896da85b3b93b39c2c92cde352deec3c`.

Separate Quality run `38510082539` fails formatting before strict workspace
Clippy or workspace tests. Its original log ZIP is
`dc81f3443896e67a3883fcc8ec4b0bb5b5e5b4839d1fb017e17081c9caf4808a`.
The exact hosted formatter output has been applied and its eleven resulting
files checked by hash. The three Clippy corrections preserve the same lazy
deadline fallback, unit-output polling and test behavior; no lint gate is relaxed.
The corrected revision passes the targeted core/guest/quote run above. Separate
Quality `38511036689` passes formatting, fuzz lint and dependency/license checks,
then stops at `struct_field_names` in the CLI's private `PublicPolicy` type.
Workspace tests, including the eight new agent/control/CLI cases, are skipped.
Its original log ZIP is
`73cd058d0f2d9554d0676dd48bb809aaea88c44e63bcaa05edf6b5265ba5bf99`.
Renaming that private type to `PublicExpectations` leaves the JSON
`public_policy_id` field, strict schema, policy criteria and CLI options unchanged.
Earlier CodeQL `38511032900` on `85a01382` passed, but did not replace
that source's failed Quality result.
Independent review confirms the narrow correction. Corrected source `09b0d3cc`
passes targeted run `38512217556`, Quality `38512223814` and CodeQL `38512218075`;
PR247 is merged as `17afa3f0`. The Quality result includes execution of all eight
new agent/control/CLI tests. Namespace-dependent checks skipped by runner policy
are not production-route evidence. No local Rust tool was run.

### Guest-owned protected-compute session candidate

The [guest module](development/PROTECTED_COMPUTE_VERIFIER.md#guest-side-session-candidate)
adds an internally generated ephemeral key, canonical challenge-v2 handling and
the real pinned-library `SNP_GET_REPORT` call on the fixed Linux guest device.
Finite owner/attempt limits, one active slot, cancellation, replay checks and
bounded request/response codecs belong to the same session. A cancelled in-flight
firmware call retains its slot until it returns; cancellation does not claim to
interrupt an ioctl. Production cannot select the synthetic source used by tests.

Original hosted run
[`38502691198`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38502691198)
on `62261f3e534c237f0fbfa4b5906bb3fd8c6fadf9` passes compilation, all 52 existing
appraisal tests, targeted Clippy and all 16 new Rust lifecycle tests, with zero
failures or ignored tests. The 64 existing inert harness tests, 12 guest evidence
contracts and 12 public-RSA source/graph regressions also pass. Independent Rust
and harness review finds no blocking issue. The new receipt cannot promote
software tests to hardware verification, worker admission or private execution.
The guest key is process-owned, not proven hardware-nonexportable. Approved images,
authorized model/runtime assets, protected stream wiring, complete appraisal and
a real confidential-computing two-node trial remain open.

Independent reconstruction and root replay bind both original artifacts to tree
`88bb1a2027e690934dcf3303b41b9329a764c071`, the unchanged committed lockfile and
resolved dependency projection. All five command leaders are joined, without
capture errors. The 15-file core artifact ZIP is
`240f34c904c9c852a3811f1fb47e9580dcae1329fe140451ab93d35b14c2797c`;
the three-file guest artifact ZIP is
`3752bfe480b9218016f2f1f0189d5ddb23ef2fef31f6bea43aad6c95966f7a92`.
The guest receipt binds the exact original prerequisite report and retains false
firmware-success, hardware, full-appraisal, worker-admission, private-input and
protected-execution scopes.

Quality `38502695418` passes strict workspace Clippy and the same 16 guest and
52 appraisal tests. Its exact merge checkout has the candidate tree. Unfiltered
summaries total 3,635 passed, zero failed and seven ignored, excluding six filtered
child summaries. Three namespace probes are explicitly skipped; the non-mutating
harness also has one Python skip. These are not live network or hardware proofs.
The original Quality log ZIP is
`284ab161b7d44f2693d9cc39359c198b69b1b7b1541c61aaeb81abcfb068c48f`.
CodeQL `38502691747` passes all four analyses and its aggregate, with no reported
findings. The Rust extractor retains two file diagnostics, so extraction is not
complete or error-free. Its original log ZIP is
`78c734ff952b4f07d3ed83005454afe82f515304e293bc31a6477c9be060369c`.
The reviewed software slice is integrated through
[PR246](https://github.com/VOLPAROSSA/volparossa/pull/246), merge `e282a3ce`.

The first hosted attempt `38501558705` on `ce3dd8c5` passes all 64 existing inert
checks but fails one new permissions fixture before compiler installation. Under
the runner's `umask 077`, `mkdir(mode=0755)` creates a safe `0700` directory; the
test incorrectly expected rejection. The fixture now explicitly applies `0755`,
without changing the production gate. Separate Quality `38501620664` stops at
formatting; its exact formatter changes are applied without running Rust locally.
Neither failed run establishes compilation, Clippy or the 16 Rust lifecycle tests.
The first run's original log ZIP matches SHA-256
`b38bd2fe33bf6d2e9dc7d3391ee8e678b33b50db0572fd0dbb79804800a5f4dc`;
its API lists no result artifacts because preparation was not reached. The corrected
12 guest contracts pass under both `umask 077` and `022`, and all 12 public-RSA
scope regressions pass with the formatter-only guest-source hash updated.

The second attempt `38502007781` on `12086fca` compiles and passes all 52 appraisal
tests, then fails strict Clippy on two test-only expressions: callback type
complexity and unchecked `Instant` subtraction. Its guest tests are not reached.
Quality `38502011206` records the same genuine errors before its final cancelled
status; workspace tests are skipped. A test-only type alias and checked subtraction
fix those expressions in `62261f3e`, without changing production behavior or
relaxing the lint gates. The original failed core and guest artifact ZIPs remain
`9dd366afebbc556527f676fc860113db526b0848ee1084e8b2360a249fbb41b3`
and `a11b3feeb5893064df1da7d4b25b52483a7a3b816a5540a9d3cfb8c3b876041b`;
the original cancelled Quality log ZIP is
`504419253efacb0c79e18a0e6fafab0f4c023d62b68908b6a20a8dfb2d200905`.

### Installed Android Weather lifecycle integrated

Weather [PR19](https://github.com/VOLPAROSSA/volparossa-weather/pull/19) is merged
as `ad10d7d9ae8ba183c477192102d57c15f51be055`. Its tree equals the tested source
`576550f32b27f10015f1852ac7ecd5c85c99960f` exactly. Original Android run
[`38497919547`](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/38497919547)
passes the installed app's exact initial weather/air-quality rows, actual tap
refresh and changed missing value, real background/resume, and suppression of
expired tables. It keeps the original 4,500 ms product lifetime and 6,000 ms pause;
both products have exactly three requests. The constant-size lifecycle observer
avoids another full UI snapshot before HOME without changing production expiry.

Independent reconstruction binds all 15 original step logs, unchanged source
pins, the offline APK receipt and the final report. App/forward removal, emulator
and VM drain, temporary directories, process ownership, namespace/policy state
and restoration of the original KVM ACL all pass. The 45-member proof ZIP is
`cb9dda17f07c19bcdfa7f3fce066b1b14ea36e084ee58e556ef0793c70dc7dbe`;
original logs ZIP is
`db344da5d8317ab22d27bb3214464703e229190a824fea124be35669993583f4`.
The separate debug APK has SHA-256
`6592dcba0b2039e989b94de525b35e7249766b5d10658fc39ec26324f3eb4924`;
it is a test build, not an authorized client release.

Component run `38497925414` passes on the identical merge-checkout tree; its
original log ZIP is
`f395d3085d289a1d2dc533a0d8384d600d45b6324d7f4956acf331e14d5d1ba6`.
All six PR checks pass. This proves mounted-widget tables and real Android actions
against synthetic products in a disposable emulator, not physical phones, iOS,
live origin acquisition, mobile core delivery or Android network participation.

### Storage candidate component checks

Quality `38497060046` passes on the exact `0057262e` tree: strict locked/offline
all-target/all-feature Clippy, 3,668 unfiltered workspace passes, seven explicit
ignored tests, and six separately counted owned child passes. All eight selected
provider-refresh cases and 18 typed diagnostics pass. Three guarded namespace
skips and one inert Python skip are not live datapath evidence. The original log
ZIP is `0837eeaa7672edd8867fc167fadf54961a087678cc6991b6da4eb492345b1d1e`.
CodeQL `38497058053` passes all four analyses and aggregate status on that source;
the original log ZIP is
`e04b1c439be2a87270f2d27cabfedc640c2b70034799e6100b30176dda190ac7`.
These independently checked results do not substitute for the original actual
storage trial `38497089463`, which has now failed at `storage-consumer-publish`.
Its Cloud receipt contains one failure for fragment zero/copy zero: FINALIZE,
`wire_receipt/io`, with no correlated agent code or detail. This boundary does not
identify a cause or establish custody. The 76-member original artifact ZIP is
`d4fe157a03c2712f79176d08651820a258624cad7148f4166ef21485d733020a`.
Local cleanup reports zero owned objects and unchanged surrounding host state;
consumer remote cleanup and provider usage remain unconfirmed. Independent audit
and root replay of the originals confirm the separate base cycle: restart/resume,
three replacements, two non-consuming byte-verified restores, deletion of all
eleven retained copies and zero final base-provider usage. The failed combined
report still rejects at the acceptance gate; this base result does not establish
consumer repair or restoration. One provider's broad protocol-error count is
uncorrelated and does not identify the Cloud failure's cause. The original log ZIP
is `f745d42ad072ca38f34a376b57f6784f347a8c6ffb9df7d94bee1ecfc11bee03`.

Candidate `506b4c49` adds one provider-local, closed operation/phase/error-family
tuple alongside the existing error event. It distinguishes backend failure from
receipt failure after an operation may already have committed; it does not add
a wire reply or establish a request correlation. The bounded diagnostic sidecar
keeps exact v1 compatibility and adds at most 32 observed tuples per role in v2,
with explicit omissions and unchanged size limits. It exports no identifiers,
addresses, paths, keys, payloads or nested error text. Deadlines, retries, quotas,
authorization and the blocking worker's disk permit remain unchanged.

Independent source review, 62 inert smoke checks and 41 wiring checks pass.
Diagnostic revision `b9a8905e3b0b95d0e44cd41d083776cf0fa0b86e` passes original
Quality run `38505948590`, including strict workspace Clippy and all eleven new
Rust regressions. These cover a lost receipt after a durable commit, actual
database/integrity/lease errors, outer timeout and cancellation with a still-owned
blocking permit. The content suite reports 192 passes, zero failures and zero
ignored tests. Three namespace probes and one inert Python case are skipped;
these component results are not live consumer acceptance.

Original CodeQL run `38505945732` passes all four analyses and its aggregate;
two Rust extraction diagnostics remain explicit. Independent reconstruction
and root replay bind the original logs and API results to tree
`7b6d96080ca6a6e0f56345e11164fc1717ff03b6`. The Quality log ZIP is
`56ec2335afc2177a83b043dcf80875d9cd3533321baa4e0dadf1c655175b1f11`;
the CodeQL log ZIP is
`8c8870bf2f08c0516aedfc3bbaa3e335ebe2fe3335ce1e550dd79b8b86f1acc4`.

Actual Image/Cloud trial
[`38508516347`](https://github.com/VOLPAROSSA/volparossa/actions/runs/38508516347)
fails on that exact revision. Image publication stops at fragment zero, copy one,
with intended operation FINALIZE, `agent_ready/agent_rejected`,
`CONTENT_UNAVAILABLE`, and detail `tls_handshake/none`. This is a local preparation
observation: that attempt never reaches the provider's FINALIZE/challenge/READY
or storage backend. The provider sidecar has no storage failure tuple for it,
which neither identifies a cause nor proves absence of a transport error.
Cloud publication, consumer enrollment, repair, restore and deletion do not run.

The separate base trial passes service restart, cursor progress from 3 to 4 to 8,
a fresh-owner nine-fragment result, three replacements, two non-consuming
hash-verified restores, deletion of eleven retained copies and zero final usage
on all three base providers. These are not consumer results. Consumer-local
cleanup removes 20 directories and 38 files with no process left; remote cleanup
and provider usage remain unconfirmed. The combined acceptance gate rejects the
report. The disposable guest's root-network state is unchanged.

Independent reconstruction and root replay verify original metadata, all 76
artifact members and receipt hashes. The artifact ZIP is
`33285c55e9230844eded7da8b67b7c32aa04d6fe4bcb9c9baf4aaa48cc81d62d`;
the log ZIP is
`ad69cda61c65610771740883795651a35a606e81580008549590955c52828cae`.
The equal before/after root-state hash is
`f618c7aed6548ab65465235ea1e402ae33dfb2ce12b95e66a4bbfa132c20b8cd`.
The earlier Cloud `wire_receipt/io` failure remains a separate observation;
neither run establishes the other's cause.

Candidate `c0b2b62b` adds six closed request-local TLS classes: offer,
configuration, actual handshake deadline, authentication, other TLS and I/O.
The optional wire field preserves old readers and the existing result/code/Ack;
enclosing deadlines and cancellation clear the TLS observation. No raw error,
identifier, address or payload is exported. A returned TLS error can originate
in the carrying protected stream, so it is not attributed to the provider.
Timeouts, retries, quotas, policy and resource scheduling are unchanged.

Current CLI diagnostics use version three. Historical versions one and two keep
their exact shapes. Consumer profile four pins Image
`3b5830476dabd548debfdfade4fdf72acb4fa992` and Cloud
`ea24b6cd53a14b204a7b8fbfda5c76ec9ca297e7`; all 23 pinned source blobs are
verified, and profiles one through three are unchanged. The hosted acceptance
command explicitly requires the new profile while historical replay remains
available. Image's 50 adapter checks, Cloud's seven diagnostic/provenance checks,
108 inert consumer checks and the new positive/negative CLI gate checks pass.
The fifteen new Rust regressions still require hosted compilation and execution.
This is diagnostic preparation, not a repair: actual publication, maintenance,
restore, remote deletion, provider usage and cleanup must still pass together.

Joining current `main` preserves published quote request tags 43–45 and response
tag 33; the unmerged storage-maintenance operation moves to free request tag 46
and response tag 34. Old storage-candidate encodings are not compatibility aliases.
Four new wire regressions freeze the quote encodings and reject the old maintenance
bytes instead of interpreting them as quote authority. The existing non-overlapping
provider refresh now also recognizes a live quote-only service; a fifth regression
covers registration and withdrawal after deactivation. These five integration
regressions, like the fifteen TLS cases, still need hosted Rust execution. No local
Rust tool or active host-network configuration was used or changed.

Quality `38516807829` on merge `82c85276` stops at formatting. Its actual PR
checkout `4dce53ec` has the same tree `6ab983224611e2017b0c347fc006b9b2e03871ad`.
The original log ZIP is
`0091792b1500ee6e562d76169c82367a2f1b86dc9624ea02197eae37bde30239`.
Nine formatter hunks across eight files have been applied from that original
output, without a local Rust invocation. Shellcheck, Clippy, dependency checks and
Rust tests did not run in this attempt; corrected hosted acceptance remains open.

<!-- END HISTORICAL LEDGER EXCERPT -->
