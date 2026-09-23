# VOLPAROSSA v1 implementation status

This is the repository's source of truth for implementation progress. A checked item means the repository contains the implementation and its stated verification has passed. Architecture documents, interfaces, disabled tests, mocks, simulations, and single-path fallbacks do **not** satisfy dataplane requirements.

Last updated: 2026-09-23

The completed development milestone is integrated into `main` by
[PR #150](https://github.com/VOLPAROSSA/volparossa/pull/150), merge `322c45b9`, after the
unchanged normal Quality/CodeQL checks and source-exact provider/recovery audits passed.
The exact-object policy and explicit peer-distribution milestone below is now also integrated
by [PR #151](https://github.com/VOLPAROSSA/volparossa/pull/151), normal merge `2761b9da`.
The automatic-follow milestone is integrated by
[PR #153](https://github.com/VOLPAROSSA/volparossa/pull/153), normal merge `54c382c0`, with
normal Quality/CodeQL checks passing. Authority-round/cycle and larger-model work remain
subsequent slices. Neither integration nor execution proves reliable model reasoning.

The new explicit HTTPS checksum-file candidate connects `--checksum-path` from normal
`fetch-https`/`browser-download` through local control, protected origin streams and existing
whole-digest peer retrieval. The consumer authenticates a same-directory SHA-256 document
itself and then the resource HEAD; neither a peer hash nor its signing key supplies origin
authority. Original minimum freshness survives both requests, and full bytes must verify
before delivery or contribution. Cookie/private/no-store, ambiguous names/checksums and
conflicting digests are refused. Six focused real-TLS/parser checks (four new checksum checks
and two existing digest checks), six local-control HTTPS checks, twelve CLI content checks,
five actual CLI-process tests, the checksum-origin fixture check, and scoped strict Clippy
for CLI/agent/content/local-control pass. Seventeen inert provider-HTTPS checker tests,
scoped formatting and shell checks also pass. The extended disposable scenario exercises
origin-only retrieval, a fresh two-provider hit and wrong-checksum rejection with original
privacy/cleanup gates; its live protected-network result is pending. This
extends one public binary-download profile, not arbitrary browser capture or completed C08.

An automatic public-copy maintenance candidate adds `content retain`: the publisher enrolls
one original public object, desired copies and finite lifetime/upload budget, rather than
hand-selecting every provider key. Protected discovery returns signed route-distinct service
hints; fresh signed Inspect/Deposit exchanges establish actual observations. The controller
can seek another holder after a loss while its owner runs. Every attempted upload reserves
the full object budget durably, and resume retains original deadlines and re-inspects known
holders instead of counting historical receipts. Background discovery/transfers use the
existing configured quiet admission, per-chunk cooldown and foreground cancellation. No
provider storage-capacity promise, owner-offline maintenance, global placement fairness or
permanent availability is implied. The
[three-holder loss/replacement proof on `2a431c1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35916493141)
now passes its unchanged source-exact checkers against 174 original files. The owner chooses
R5 and R3 without provider-key arguments; after actual R5 service withdrawal, fresh challenges
establish R3 and replacement R4. The owner is then terminated/reaped with exit 0 and its source
cache/input removed. A fresh download reconstructs 2,097,275 bytes using 1,048,699 unique peer
bytes from two providers and no origin bytes. Original manifest/expiry/window and cumulative
upload reservations are retained. All 52,559 captured frames, cleanup and unchanged host state
pass. The publisher application stops, not the full Client node; no future availability,
owner-offline maintenance, global fairness or model-governance completion is established.
Three protocol, five real custody-stream, two background-admission and 48 CLI content tests
pass, along with the existing real CLI custody-process trial. Strict scoped Clippy for the
CLI, agent, content and local-control crates passes. An actual inert CLI preview accepts the
owner enrollment without requiring files, key unlock or a running agent. These local checks
do not substitute for automatic remote placement/replacement evidence.
The disposable fixture now enrolls two copies without provider-key arguments, withdraws one
actual service, requires a third holder's original signed exchange, then reaps the publisher
owner and removes its source before a fresh protected named download. Original deadlines,
upload reservations, challenge freshness, privacy captures and host cleanup remain checked.
Seven focused inert retention-fixture tests and four existing custody checks pass, together
with scoped shell checks and the existing inert topology contract. A deliberately exited
owner remains a failed trial while its private fixture files can still be cleaned up.

A new node-local policy candidate connects the original four signed assessment/review
transcripts to `compute peer policy-propose`, `policy-endorse` and `policy-combine --execute --apply`.
Each command uses explicit `--policy-config` and independently reopens the selected evidence;
compute-provider keys never become policy signers. The existing separately configured authority
quorum signs an exact native subject (publisher, manifest ID and complete-object digest), bound
to the current policy epoch, original evidence, decision revision and expiry. The agent verifies
and durably retains the original quorum bytes before updating one shared live gate. Restart
revalidates them; lower revisions and same-revision conflicts cannot replace the retained floor.
Known denied, undetermined, expired or old-epoch objects are withheld. Unassessed objects still
need their existing publication authorization; absence of a decision is not a new approval.
The gate connects native acquisition/serving, queued contribution, custody and replication
intake rather than copying rules into stale registry snapshots. Twenty-three focused Rust
checks and scoped strict Clippy pass locally, including actual in-flight withdrawal, denied
intake/queued copies, mixed-publication restart/reclaim and an isolated custody-service lifecycle.
The [first extended disposable proof on `6ac301ee`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35893332294)
**failed** in its restart-evidence checker: it confused manifest schema/version 1 with the
existing minimum policy protocol version 2. The 170 retained originals contain the actual
three-authority `undetermined` decision, successful local application, unchanged original
journal/authority bytes across restart, and `CONTENT_POLICY` cache refusals before and after
restart. All four model jobs still contain reasoning errors. A prospective check changing only
that protocol expectation passes the retained evidence, including captures and cleanup;
the original run remains failed and emitted no final activation report. The fixture now
distinguishes the fields and has a focused schema regression.

The next candidate adds `compute peer policy-publish` and `policy-import --execute --apply`:
original quorum bytes travel as an inert signed native object through existing protected
custody transport. A receiver verifies the exact subject, decision and evidence pins under its
own configured current authority, then uses the same durable local gate. The content publisher
does not become a policy signer. Original decision bytes and expiry survive publication,
import and retry; no model or signing key needs to be transferred to the receiver. The extended
fixture requires a genuinely cold decision on a separate node, actual custody receipt/export,
fresh subject-access probes, and unchanged authority after that receiving agent restarts.
Seven focused CLI checks, strict CLI/agent Clippy, and inert fixture/shell checks pass. The
[source-exact peer-distribution VM proof on `4d438099`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35896887925)
now passes its full committed checker against 199 unchanged original files. Four real model
jobs produce an `undetermined` / `review_disagreement` result. The separately configured
three-authority quorum authorizes that same result; its 605 original signed bytes reach a
previously cold second node through protected custody transfer. That receiver verifies its
own authority and applies the exact-object decision without new model work or signing keys.
Both nodes serve the original cached subject before application and refuse it with
`CONTENT_POLICY` after application and after their actual agent restarts. Original decision,
epoch, expiry and journal records remain unchanged. Five capture records contain 96,199 frames;
full cleanup and unchanged host state pass. The original model responses still confuse
principle meanings and contain unfinished prose: correct transport/enforcement is not sound
judgment, independent reasoning or legality. Automatic channel subscription, network-wide
membership/conflict governance, physical cache erasure, arbitrary HTTPS inspection and B06
completion remain open. The earlier `6ac301ee` failure is not relabelled.

A subsequent `compute peer policy-follow --execute` candidate automatically refreshes one
owner-enrolled native publisher/name channel and applies only quorum-verified decisions for
its exact enrolled subject/framework under the node's own current policy configuration.
The selected signed wrapper must be registered in the serving peer's live name-enabled registry;
raw cached chunks alone are not a named publication. Complete custody admission can register
the original publisher's wrapper; it does not create a wrapper under a different peer's name.
The bounded serial loop retains original wrapper/decision/epoch bytes and transport/application
receipts, enforces publication and decision revision floors, and skips unchanged publications.
SIGINT/SIGTERM stops its own work without disconnecting shared consumers. `--resume` requires
the same enrollment and preserves pending handoff and original expiry; it never signs a new
decision or turns an expired/historical receipt into current authorization. Explicit polling
and cache limits require no model work or transferred private keys. Automatic spare-bandwidth
scheduling and measured interactive non-interference are not claimed for this follower.

The new fixture keeps the same four model jobs but combines without direct application. It
starts the follower with a fresh cache before the receiving peer publishes, requires an actual
completed unavailable poll and empty Client journal, then binds the real protected named
download and automatic apply acknowledgement to the unchanged original quorum. Follower
reaping, cached-access probes and both real agent restarts remain mandatory. All 11 focused
object-policy CLI tests pass, including four new follower checks, along with strict CLI
Clippy, scoped formatting and shell checks. Its inert Python self-test
passes with 81 rejection cases. The separate
[automatic-consumer proof on `3f30a5f9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35899595361)
passes its complete committed checker against 208 unchanged original files. Before publication,
the same live follower records an actual failed poll with an empty cache and no applied decision.
It subsequently fetches 605 original quorum bytes through protected peer transport with no
origin bytes and applies once; combination itself did not apply. Actual Client and receiving
agent restarts retain the original decision, epoch and expiry, and cached subject access remains
withheld. The 101,947 privacy frames, follower reaping, complete cleanup and unchanged host
state pass. The model reasoning errors remain visible. Neither the failed `6ac301ee` nor the
passing manual-import `4d438099` is substituted for this separate automatic proof.
This is selected-channel automation, not a complete global feed, new authority membership,
independent semantic accuracy or B06 completion.

The next development candidate adds `compute peer policy-round` and `policy-authority`.
A finite coordinator packages the original assessment bundle and unchanged proposal, delivers
them through protected public custody, collects separately selected single-authority replies,
and publishes only after verifying the node's existing full quorum. Each authority independently
replays the four original signed transcripts and keeps its signing identity local; the coordinator
has only its content-publisher identity. A typed local inbox reads the active contribution registry
without opening agent-owned storage in the CLI or requiring a service-only node to become a
consumer. A durable per-identity reservation rejects same-revision conflicts and rollback before
signing. The result can be contributed locally or deposited at explicitly enrolled publication
peers, preserving the original wrapper, decision and expiry. This starts from a completed original
assessment bundle; automatic initiation of new model assessments is not claimed. Thirty-five
focused policy, wire, registry, CLI and isolated custody-lifecycle checks pass locally. Strict
Clippy passes for the five affected crates and the guarded development-identity helper. The
disposable fixture now exercises three separate authority owners and a genuinely parallel cold
follower; its inert checker passes with 86 rejection cases. The source-exact
[three-authority trial on `75e7ff52`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35907082514)
**failed overall** at the receiving agent's post-restart cache-access probe: it returned
`CONTENT_INVALID` instead of the required `CONTENT_POLICY`. Original evidence nevertheless
records four real model jobs, three separately owned endorsements, verified quorum publication,
cold follower retrieval of 605 peer bytes with no origin bytes, and Client restart persistence.
Its 100,994 privacy frames and cleanup/unchanged-host checks pass. The receiving-agent check
remains failed; the original error does not identify the underlying cache error. The candidate
fix authenticates a transfer manifest and checks its object policy before opening its cache,
so a busy cache cannot mask a valid withholding decision. A real locked-cache test covers that
ordering. Model reasoning errors and an `undetermined` final decision remain visible; this is
not a claim of reliable semantic judgment or a passing full trial.

A subsequent `compute peer policy-cycle` candidate removes the manual handoff between model
work and that authority round. It acquires one independently selected public native source,
executes the original two assessments and two cross-reviews, replays their exact signed bundle,
and passes it directly to the existing independent-authority round. One durable enrollment
binds all selections and the original total deadline. Resuming observes existing handles and
may start previously unstarted subsequent stages, but never replaces ambiguous/submitted work.
Cancellation reaches the existing job protocol; unconfirmed remote termination stays explicit.
The current quorum is checked before model work and again by the signing round. No authority
private key or human-supplied verdict enters the coordinator. The combined cycle's first
[exact-source network trial on `4eb06de2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35910694773)
**fails overall**: assessment-0 returns `preflight_unavailable` before retaining a job handle;
assessment-1 completes, but the two cross-reviews and authority round do not execute. The
original specific preflight error was discarded, so discovery, resource pressure or a local
failure cannot retrospectively be selected as the cause. The retained packet captures and
cleanup/unchanged-host checks pass separately; they do not establish the combined cycle.
Earlier assessment/follower proofs do not establish this composition, reliable semantic
judgment, automatic authority membership or B06 completion. A follow-up retains a bounded
local preflight diagnostic without remote text, new retries or a changed operation deadline.

The separately instrumented [exact `2a431c1` trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/35916895065)
also **fails overall**, but reaches all four original assessments/reviews: their observed
workers, signed receipts, source/quote bindings and isolation pass the source-exact first
gate. The cycle then stops in its authority round with
`policy_round_request_custody_retry_bound`: 64 retained incomplete request-deposit batches.
The fixture exited before exporting those per-provider deposit records, so their underlying
handoff failure cannot be attributed to contention or transport from these originals. The
192,423 captured frames, cleanup and unchanged host state pass separately; no quorum,
automatic activation, follower restart or full-cycle success is established. The earlier
preflight failure did not recur, but is not relabelled or retrospectively explained. The
360M model outputs still misidentify principles and include unfinished prose; their retained
decision is `undetermined`, not evidence of reliable legal or ethical judgment.
A fixture-only follow-up retains bounded original cycle/round status and failed deposit
receipts before returning that same nonzero failure. It neither increases retries/deadlines
nor claims to repair the as-yet unattributed custody failure.
The combined fixture requires the original source, four worker receipts, exact bundle, three
authority owners and one original cycle deadline; its inert checker passes 91 rejection cases.
All 31 focused assessment/round/cycle CLI tests and strict CLI Clippy pass. Five transfer tests
pass, including policy refusal while the actual cache is locked. Named retrieval now waits FIFO
behind an existing retrieval within its unchanged total deadline, rather than rejecting a
source fetch when a follower is active. Two focused admission tests pass, covering serialization,
requester disconnect and deadline cleanup; no detached waiting work or extra network jobs are used.
Strict agent Clippy, scoped Rust formatting, fixture ShellCheck and topology shell syntax pass.

An explicitly selected `smollm2-1.7b-v1` inference candidate now addresses the observed
reasoning limitation without replacing the lightweight training model. It pins the original
SmolLM2-1.7B files, reuses the existing CPU runtime and verifies actual CPU BF16 parameter
storage. No training, 135M adapter application or silent FP32 fallback is admitted. Public and
local-private inference, document/graph planning, grounded synthesis and principle-assessment
interfaces retain the same token and time budgets. Existing 135M/360M defaults and historical
enrollment encodings remain unchanged. New non-default policy enrollments retain the exact
profile and original provider fingerprints; resume cannot upgrade either.

The selected larger profile has explicit 5-GiB sampled RSS and 10-GiB address-space bounds;
pre-launch admission and broker availability require at least 5.5 GiB observed spare memory,
including cgroup parents. This is not a memory reservation or a hard RSS cap. Owner pressure,
two-thread limits, isolation and cancellation remain active. A separate 8-GiB single-worker
`agent-reasoning` VM scenario retains the same original 444-byte public source and question
used by the earlier flawed graph, plus its actual answer and execution observations. Content
review remains distinct from execution/EOS. Ninety focused Rust tests, strict production
Clippy for the CLI/agent/content library, inert Python profile tests and the inert KVM launch
contract pass. The [first exact-source VM trial on `6786bfa4`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35879772476)
**fails overall** at the address-space observation. Its real BF16 worker completes in 79.776
seconds, generates 43 tokens and is reaped; the supervisor observes a 3,908,026,368-byte peak
RSS under the selected 5-GiB sampled limit. The original answer correctly selects Route A
because it hides the client address from the exit, but omits Route B's violation, the relay's
destination boundary and all requested performance evidence. Complete correctness is not
proved. Isolation/input checks, final owned-object cleanup and unchanged host bytes pass.
The observer's parser incorrectly rejected padded kernel columns, and it did not retain the
original row: no retrospective claim about the actual 10-GiB limit is possible. A follow-up
now retains the raw limits, parsed numbers and PID/start-time binding, while preserving exact
10-GiB soft/hard validation. The failed run remains failed. The follow-up
[exact-source VM trial on `3d57f418`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35883858055)
passes its full single-worker execution checker: original raw limits prove 10-GiB soft/hard,
170 CPU observations are retained, the BF16 worker completes in 83.956 seconds with 190 EOS
tokens, and supervisor peak sampled RSS is 4,073,488,384 bytes under the 5-GiB limit. Original
weights remain unchanged, the child is reaped, cleanup is complete and host hashes match.
Larger-model peer/policy execution and general answer quality remain open; no model or backend
ran on the development host.

A small functional follow-up adds the `public-source-parts-v1` instruction to new public
answers and grounded synthesis: answer all requested parts, separate missing evidence from
supported conclusions, and treat source text as data rather than instructions. It preserves
the exact supplied source/question and existing token/time budgets. Tokenizer planning counts
the same prompt; optimizer/heldout-loss, private, policy and historical source-free synthesis
prompts remain unchanged. Completed resume results are not rewritten. New reports identify
the instruction revision without pretending that model-weight fingerprints attest prompts.
Focused inert tests pass. The real follow-up answer now identifies missing throughput, latency
and failure measurements, but repeatedly asks whether the exit can handle the client's public
address, contradicting the source boundary. It also omits Route B's violation. Complete
correctness and controlled quality improvement are not proved; the original answer is retained.

A subsequent candidate fixes a concrete admission mismatch: the worker already accepts the
rich-inference 360M/1.7B profiles for version-4 principle inputs, but local `compute run` still
rejected 1.7B. The gate now uses the same capability predicate while preserving inference-only,
no-adapter, public-input and fixed-contract restrictions. Five focused admission tests pass.
The existing 8-GiB single-worker fixture is now directed at one real, signed public principle
assessment with the current framework and explicitly provisioned pinned JSON decoder. The
unchanged 1024-token prompt, 512-token structured generation, 2048-byte JSON, 192-byte field and
600-second limits remain in force. The
[exact-source trial on `44eec3b9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35912302153)
passes its original execution checker: one real BF16 worker produces 293 tokens in 62.132
seconds, with 4,596,285,440 bytes of observed peak RSS, the actual 10-GiB address-space limit,
original signed inputs, child reaping and unchanged host state. Its answer correctly connects
Mansuetudo to gentleness and voluntary cooperation, but invents absence of ulterior motives
under Humanitas and infers humility not established by the source. It also chooses `allow`
while reporting material uncertainty. The original answer remains visible; this is not a
general semantic/legal pass, independent cross-review or policy activation. The changed
question/pipeline prevents attributing differences solely to model size. The distributed
cycle remains on its original 360M source.
The scoped CLI build/Clippy, inert fixture checks and an actual offline CLI preparation pass:
the current framework and three freshly signed public publications verify unchanged. No model,
backend provisioning or network work ran on the development host; temporary input was removed.

An owner-enrolled `compute train-loop --aggregate-plan` candidate now connects automatic
three-publisher discovery, frozen-cohort aggregation and held-out comparison to local adoption,
serving and the next actual training warmstart. Unchanged cohorts are not recomputed; rollback
or same-revision forks are rejected. The active model, not an assumed base, is the comparison
baseline. Original authority deadlines propagate through aggregation and local successors.
Interrupted rounds retain their inputs and do not silently restart; completed results can be
reopened after coordinator restart. Storage is bounded and only exact owned round files may
be reclaimed. The mode requires independent pinned validation and excludes individual-peer
adoption in the same enrollment. Compilation, 97 focused training checks and strict CLI Clippy
pass. The [complete automatic run on `aa2eb344`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35874130419)
passes exact-source checking: three real 8/9/10-step contributions, cold automatic intake,
genuine aggregation and eight further local warmstart updates. Both local approval metrics
improve in this tiny fixture: four-token source loss 1.114049 to 0.605543 and seven-token
second-source loss 1.937618 to 1.462681. The exact approved local successor serves a protected
peer job; ten original worker observations, both captures and all cleanup/host-state checks
pass. Restart retains completed bytes and original expiry, verifies the unchanged cohort once
and performs no new training. This does not establish general answer quality or independence
of the contributors. Automatic publication is not part of that run.

A further executable candidate now connects approved aggregate
publication to the loop's existing owner-authorized publish settings. Combined and local
updates share a durable revision order; retries reuse original signed bytes, completed receipts
can settle interrupted checkpoints, and neither retry nor resume renews authority. Pending
publications survive reclamation and share the existing bounded drain. The
[complete return-sharing run on `8d4bb840`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35876746847)
passes exact-source checking of all 204 original files: three real 8/9/10-step contributions,
aggregation, eight local warmstart updates, automatic aggregate revision 1 and approved local
revision 2, and a drained monotone publication queue. A separate cold Client retrieves original
signed revision 2 and its dataset through relay4 and uses the exact returned weights. Restart
preserves original publication/serving bytes and expiry without another training attempt.
Eleven actual worker observations, network captures, complete cleanup and unchanged host bytes
are retained. The receiver's actual eleven-token EOS answer, however, says "There are 2 relays
in each parallel path." That is factually wrong: each path must have exactly one relay. Local
serving answered "One path uses 1 relay." These different retained answers do not invalidate the
weight-transfer evidence, but neither EOS nor improved tiny heldout losses prove sound reasoning.
Standalone `compute publish-aggregate` remains available. General quality, broader corruption
recovery and full B05 remain open; the narrower aggregate recovery proof follows below.

An integrity-recovery candidate now handles a damaged selected aggregate or approved local
successor before restart validation, serving de-duplication and subsequent warmstarts. Only
changes confined to the three extracted adapter files qualify; original bundles, approvals,
signed sources and snapshots remain immutable. Serving admission is withdrawn before selecting
the exact still-approved, unexpired predecessor. No predecessor means no base fallback or new
lease. Retirement survives restart, invalidates unfinished comparisons against the damaged
baseline, preserves historical counters, pins direct predecessors within bounded retention,
and removes retired selections from publication retries without recycling revisions. All 97
focused train-loop tests and strict CLI Clippy pass. These include a complete inert local-to-local
rollback/withdrawal and historical second-source verification, not real model execution.
The existing disposable `agent-autonomous-aggregation` scenario now includes that candidate's
local-successor-to-aggregate case after retaining the original training/publication evidence.
It requires a genuinely approved successor C, damages only its extracted weights, resumes the
original approved aggregate A twice and submits a protected peer job using exact A weights.
It then damages A's extraction and requires blocked resume plus withdrawn broker admission:
the pinned base is not an approved predecessor. Original approval, expiry and counters must
remain unchanged; one additional bounded inference reuses the existing guest runtime.
The [complete run on `3acc5dd8`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35888432967)
now passes the exact-source checker over all 247 unchanged original files. It restores approved
A after the controlled one-byte C extraction fault, preserves A's original approval and expiry
across restart, and observes a protected inference worker using exact A weights. Damaging A
with no approved predecessor then stops resume with `aggregate_retirement_no_verified_predecessor`
and withdraws broker admission. Original model/publication records, three capture sets, zero
remaining owned objects and identical host bytes pass. The cold C answer still claims two relays
per path, and restored A's answer contradicts itself about whether the source gives a relay count.
This proves the scoped recovery/withdrawal mechanics, not successful aggregate-to-aggregate
rollback, independent remote training attestation, reliable reasoning or completed B05/B07.

A source-grounded synthesis candidate now addresses the observed loss of original evidence
between model-graph tasks. New 360M `--plan-task-graph --grounded-synthesis` workflows retain
the complete original document (at most 4096 UTF-8 bytes) separately from generated parent
answers. V5 derived packages authenticate those bytes against the original signed source;
tokenization and actual inference share one prompt under the unchanged 1024/256-token budgets.
Historical v3 workflows keep their exact source-free synthesis contract on resume. Three
tokenizer-plan checks, 59 focused document/graph/replay checks, nine derived-source checks and
seven inert worker checks pass. The [grounded run on `c4bd274`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35868855324)
also passes complete source-exact checking: all five jobs use their original signed results,
dependent tasks retain the complete 444-byte source, all answers reach EOS, and offline resume
retains 114 original files with no new work. Captures and cleanup pass. The final answer still
incorrectly says that an exit learning the client's address satisfies the privacy requirement.
This fixes information loss and proves execution, not reliable reasoning or completed B03.

The [complete recovery run on `c4bd274`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35868906953)
now passes: real P/Q training and approval, local Q corruption, restoration of original
unexpired P, coordinator restart and eight further optimizer updates from a newly published
catalog source. Parsed original job receipts remain unchanged; all seven protected network
phases, cleanup and host-state equality pass. The source-bound numerical probe reports actual
60-module gauge/outlier and rank-six/rank-four projection checks plus callback cancellation;
its unit is stopped and empty. Original synthetic tensor bodies are not retained, so subsequent
review checks the original source-bound report rather than replaying the tensor arithmetic.
This is scoped local recovery, not malicious-publisher detection, complete B07 or general quality.

The [recovery follow-up on `b6984851`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35865224745)
proves further scoped progress but **fails overall**: both nodes actually train; Q warm-starts
from signed P, and the learner independently approves Q after protected cold acquisition.
Corrupting only Q's local extraction retires it and restores the original unexpired P; a new
coordinator preserves that state. Exact-weight P/Q/restored inference and five network capture
phases pass. Continued training stops at `CONNECT_ALREADY_IN_PROGRESS`; its final retained
receipt replay and the separate numeric aggregation probe are not reached. The original logs
also retain a relay4 `SHUTDOWN_CLEANUP_FAILED` event, although final owned-object cleanup and
unchanged host bytes pass. This is not a full recovery/B07 or model-quality pass.
The fixture now selects a real route before each short recovery/restart observation and
confirms disconnection after reaping its coordinator. This removes the observed overlapping
bootstrap, not the product limitation observed at that revision.

A product follow-up now cancels named/HTTPS download preparation when its local requester
closes the socket or sends premature transfer data. Request-owned streams and foreground/cache
guards are released; verified cache chunks remain available for resume. Shared route bootstrap
now belongs to a retained controller task, not to the cancelled RPC. Daemon shutdown drains
both main/DNS bootstrap owners before exact retirement while discovery remains available.
Expired-route retirement also retains its cleanup owner across requester cancellation, and a
later request can observe its completion. Fifteen focused socket/bootstrap/retirement tests
and strict agent library/test Clippy pass. The disposable `content-provider` trial now also
pauses only the exact guest helper, cancels a real named download, requires an independent
cache-only delivery, then stops the original agent during pending bootstrap and resumes the
same helper before cleanup. It retains original process identities, receipts and the systemd
wait result. Sixteen provider checks, including ten inert cancellation cases, pass. The actual
blocked-helper result is the complete `c2a601ed` proof below, not inferred from inert checks.
The legacy direct-to-agent-file fetch operations, mailbox and compute request cancellation
are outside this change.

The [provider run on `3d57f418`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35883871060)
fails before reaching that cancellation phase: all three providers deliver the original
3,932,160-byte object, but their interior bulk windows do not overlap simultaneously. Native
and HTTPS overlap measurements are negative by 396.078 ms and 107.156 ms respectively. The
ordinary HTTPS, site, user-publication and named phases pass their source-exact checks; final
cleanup leaves zero owned objects and host hashes match. The failed run remains failed.
The adaptive-only fixture now supplies 60 unique chunks (15 MiB), twenty per provider (5 MiB).
Its kernel-timestamp milestones scale by the same factor, preserving the original 5%-75%
interior-bulk fractions and the strict three-provider overlap requirement. Ordinary two-provider
vectors, production admission, pacing and timeouts are unchanged. This gives the deliberately
cold, late-admitted third connection more real payload to overlap; the follow-up below proves it.
The [exact-source follow-up on `c2a601ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35887694327)
now passes the complete provider checker, including reconstruction from all 589 original files.
The three providers' interior bulk windows overlap for 4.822 seconds on native content and
4.713 seconds on HTTPS content, with all 15 MiB/60 chunks verified. The named-download
cancellation phase also passes: after cancelling the original CLI while its exact helper is
paused, an independent cache-only request delivers 2,097,275 bytes in 164 ms without network
payload; control EOF arrives in 12 ms while the helper remains paused. The helper is resumed,
the original agent stops completely, cleanup leaves zero owned objects and host bytes match.
This proves that named pre-ready cancellation case, not every HTTPS cancellation, a speed gain
over origin retrieval or completed alpha acceptance. The earlier failed run remains failed.

A new explicit `compute aggregate-adapters` candidate now connects three independently
authorized public publisher channels to a real worker implementation and the existing held-out
comparison gate. Original bundles/dataset signatures are retained; all three inputs must bind
the same exact dataset. The isolated worker computes a coordinate median of effective LoRA
deltas and a rank-four SVD projection, with no optimizer updates or base-model instantiation.
It retains input/output hashes and measured reconstruction residuals. Only an actually approved
baseline/candidate comparison can produce a local bundle. The explicit `compute publish-aggregate`
command now reopens that approval, all three original imports and their original expiries before
signing and contributing the unchanged adapter format. Retry uses one retained manifest without
renewing its lease or claiming optimizer updates. A receiver still needs independent publisher
trust and its own local adoption gate; publication itself does not activate a model. Focused Rust
checks and 87 pure Python admission/dispatch checks cover the earlier aggregation candidate. No backend
or model ran on the development host; the real three-publisher VM result is scoped below.
This adds executable integration, not completed B05, general quality or poisoning resistance.
The new `agent-adapter-aggregation` disposable scenario connects three real 8/9/10-step
trainings to protected cold acquisition, aggregation, held-out approval, publication and
exact-weight inference on another node. Original public objects are explicitly provisioned
to one supplier without re-signing; this is not peer-upload evidence. Its first
[run on `4c821fc`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35866815840)
**fails overall** during evidence assembly: the original 587,887-byte combined network
record exceeds the reader's inherited 262,144-byte individual-report cap. The unchanged
source-exact evidence checker passes against the retained original fields assembled only
in memory: three distinct trained adapters, seven actual isolated workers, real aggregation,
held-out approval, original signed publication, protected cold transfer and exact-weight
receiver inference. Final owned objects are zero and host-state hashes match. Neither the
original report nor its failure is rewritten. The composite reader/writer now uses an
explicit 2 MiB cap, with the overall 24 MiB cap unchanged; inert boundary checks pass.
The [complete rerun on `865a38b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35869598198)
now passes without rewriting records or omitting checker gates. The three real trainings
produce distinct weights; seven isolated workers complete the aggregation, comparison and
receiver inference. The held-out comparison covers seven target tokens (baseline loss
2.5174422264; candidate loss 1.9376181364), not general answer quality. Original signed
publication, both protected transfer phases, cleanup and unchanged host state all pass.
Automatic adoption in the training loop, poisoning resistance and full B05 remain unproved.
The new cached-import and aggregate/publication checks pass (eight CLI import checks, one
cache hit/miss/revision-floor check and six aggregate/publication checks), as do command help,
scoped formatting and strict production-CLI Clippy. Clippy including test targets still reports
six existing style issues in unrelated test modules; this is not a clean full-suite claim.
A guest-only numerical probe now reuses the existing pinned runtime in a separate, bounded
private-network user unit. It checks real saved tensors against gauge/outlier and rank-six
median/rank-four projection oracles, plus cancellation. Archive-bound source staging and
inert admission checks pass; the real backend result is scoped in the complete recovery run above.

The [complete-envelope policy run on `fb574fdb`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35855257313)
**passes its narrow four-worker pipeline**. Two original assessments finish at 1,003 bytes /
289 tokens; both opposite-peer reviews now finish at 1,025 bytes / 252 tokens, each at a real
JSON boundary. Original provider signatures, exact cross-review bindings and all 144 retained
files pass source-exact checking. A 225,132-byte bundle transfers through the protected peer
path into a fresh cache/folder on the same receiving client. With the brokers stopped, replay
returns the unchanged result with zero new jobs. Five captures retain 80,173 frames with no
drops or direct Client-to-Exit traffic; cleanup and original host bytes pass.
This is **not sound or independent policy reasoning**: both assessments and reviews retain
incorrect principle meanings and unfinished prose, and identical assessors use the same model.
The concept remains `undetermined` / `review_disagreement`, with no network policy activation.
B06 is not checked off. The new review bytes explain why the 2,048-byte envelope is needed for
this run; they do not reconstruct or validate the absent rejected reviews from the older run.

The [policy run on `3dc6136a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35852279407)
reaches both actual assessments and both opposite-peer review workers, but **fails overall**
at `POLICY_REASONING_INCOMPLETE`. Each assessment completes at a real JSON boundary after
289 tokens, retaining 1,003 original UTF-8 bytes and a verified provider-signed Poll transcript.
The two texts are identical and contain terminology errors and unfinished prose: structural
completion is not sound reasoning, independent judgment or legal authority. Both review inputs
bind the opposite original assessment correctly, but the workers return `PRINCIPLE_OUTPUT_BOUND`;
their rejected text/token counts are absent, so their other validity properties are unknown.
Review of all 128 original files verifies the source/custody bindings, four real isolated
workers, cleanup and unchanged host bytes. Five captures retain 73,666 frames with no drops or
direct Client-to-Exit packets. No completed review, portable bundle or offline completed replay
is proved; the concept stays undetermined with no policy activation. B06 remains open.

The next candidate corrects an envelope mismatch: three ordinary ASCII reasoning items using
the already permitted field sizes can require 1,639 compact review-JSON bytes, while the old
whole-response gate permits only 1,024. The raw JSON envelope is now explicitly 2,048 bytes,
within the existing 4,096-byte escaped-text transport envelope. Quotes, individual explanations,
the fourteen principles, source grounding, opposite review and uncertainty requirements remain
unchanged, as do the 512-token and original worker deadlines. This does not admit oversized
wire output, repair/truncate a complete judgment, prove the old rejected reviews valid or fix
the semantic defects observed above. The later run above proves the four-stage mechanics only.
Fourteen focused Rust policy tests, thirteen pure worker tests and the independent fixture
self-test pass. Historical enrollment-v1 questions remain byte-identical on signed-dataset
reopen; new enrollment-v2 questions are unchanged. No model was run on the development host.

The [first active-recovery run on `5b86711f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35850630251)
**fails before training**, at `RECOVERY_SOURCE_SETUP_FAILED`: the fixture reads a README next
to its source helper, but provisioning stages that file under `WORK/bin`. All 103 original
files are preserved; the pinned runtime provision, cleanup and unchanged host-state bytes
pass independently. No adoption, injected fault, rollback or continued training occurred.
The corrected fixture uses the staged source and gives learner R4 its own protected route
through the existing three-candidate topology. R4 starts without training sources or peer Q
in its cache and cannot read the publisher's private directory. Original retrieval receipts
must bind those cold transfers to R5; only R5 seed/cache provisioning remains fixture-owned.
Learner acquisition and Client inference are serialized for independent path observation,
without changing original approvals, enrollment, expiry or execution budgets. Inert fixture
checks pass. The [follow-up on `bf08aee1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35852732822)
reaches catalog discovery and one attempted cycle, but still **fails before an observed training
worker**, at `RECOVERY_P_REAL_TRAINING_MISSING`. The coordinator records only `cycle_failed`;
the underlying error and cycle files are absent from the artifact. Five original captures show
both selected protected relay paths carrying traffic, not receipt-verified dataset acquisition.
R4 also reports `SHUTDOWN_CLEANUP_FAILED`; the independent final checks nevertheless find zero
remaining owned network objects, ended recorded processes, removed private stores and unchanged
host bytes. These distinct results are retained, not treated as successful lifecycle execution.
All 134 original files remain preserved. Active recovery and full B07 are still incomplete.

The follow-up retains six fixed, typed cycle-failure stages and existing typed startup/worker
diagnostics, never arbitrary source/error text. On early coordinator exit the disposable fixture
preserves a bounded allowlist of its own original state/selection/provenance; dataset plaintext
is excluded. This makes the missing failure distinguishable without changing training, cache
admission, privacy boundaries, retry policy or execution deadlines. It is diagnostic coverage,
not a claim to have repaired the unobserved underlying failure.
The twelve focused cycle tests, typed startup/EOF checks, existing diagnostic-redaction checks
and inert recovery-fixture self-test pass; no model runs on the development host.

The [diagnostic run on `f55adaae`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35856197829)
now identifies the boundary: `stage=supervisor`, startup exit 1, no signal,
`stderr_class=proc_mount`, 58 stderr bytes. The original stderr text/errno are not retained.
The original receipt binds a 1,005-byte cold dataset fetch from R5, and the bounded cycle
snapshot survives cleanup; the worker still has not begun actual training. All 135 original
files are preserved, including independent cleanup and host-state results. The fixture enters
the agent service's masked mount namespace, unlike the prior working owner launch. The next
candidate clones that view privately and mounts a clean proc in the child before dropping
privileges. Other-node storage masks, worker isolation and service mounts remain protected;
the learner probe uses the same launch prefix and checks the service mount table is unchanged.
This is a disposable-guest fixture correction, not a host mount or service-policy change.
Shell syntax and the inert launch/provenance tests pass; real recovery remains unproved.

The [child-proc follow-up on `f7ddf9e2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35858537654)
now completes actual P training (eight updates), held-out comparison, approved serving and a
protected inference using the same adapter. Cold source/validation receipts, the original
signed four-chunk bundle, isolation and unchanged service mounts validate independently.
The run still **fails**: its inference capture contains 33 unexpected Exit↔R5 TCP packets.
The fixture also performs R5's explicit seed provisioning inside that R4-only measurement;
name lookup queries other discovered cache providers even when payload bytes come only from
R4. The next candidate separates those phases without widening the traffic classifier.
Aggregate headers alone cannot attribute each original packet to that lookup. It also fixes
the evidence reader's singleton-only chunk parsing by comparing the entire canonical ordered
manifest, retaining original signatures. Inert phase-order/chunk mutation checks and the new
reader against the unchanged P originals pass. All 165 original files and cleanup/host-state
checks are retained. No Q training, adoption or rollback occurred, and the actual inference
answer was incorrect; this is lifecycle progress, not improved reasoning or completed B07.

The [separate-capture run on `e8744e6c`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35861650169)
now passes the original P training, approved publication, exact-adapter inference and both
protected network captures. All 173 original files, cleanup and unchanged host bytes are
retained. It still **fails before Q training**, with `CONTENT_UNAVAILABLE` during the initial
seed import. R5's owner-provisioned cache contains all four original P-bundle chunks and both
datasets, but the adapter importer unconditionally refreshes name metadata over a network
route that this supplier fixture does not have. The bounded cache-first import correction
retains exact publisher/dataset binding and network fallback on a miss; it does not force
offline mode or extend an expiry. No Q adoption, rollback, continued training or numerical
aggregation is proved by this run.

The [graph run on `b80f0b02`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35849837032)
also **fails at `compute_deadline`** after the actual owner reaches baseline. Its original
acknowledgments show 35.913 seconds of cooperative pauses, but no generation count, output
or precise decoder subphase is retained. Review of all 110 original files checks the exact
synthetic source/input, worker isolation, cleanup and unchanged host-state bytes. No graph
or peer execution is proved. The source-level performance correction alone has therefore
not established successful planning; neither those pauses nor the separately corrected
Unicode dead prefixes can be identified as the complete cause from this artifact.

The next graph candidate addresses another concrete source-level cost: the token traversal
now checks only existing trie edges against syntax and graph rules, rather than applying graph
predicates to the entire tokenizer alphabet at every visited node. Terminal tokens, EOS,
escaping, question/dependency constraints and all model choices remain unchanged. Thirty-two
pure decoder checks pass, including exact token-set comparisons and a synthetic operation-count
test with over fifty times fewer graph-predicate calls; that is not a measured model/VM speedup.
Public planning also emits fixed stage labels, attempt/token counts and elapsed time, without
prompts, outputs or token identities, so a supervisor deadline need not erase all progress.
Eighty-eight pure worker/principle checks, the focused Rust diagnostic check and scoped strict
CLI Clippy pass. The original 600-second/384-token graph budget remains unchanged; real completion
is still unproven.

The [follow-up on `6b44bf20`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35853354349)
now reaches genuine generation: attempt 1 records at least 368 tokens, with its last progress
at 399.494 seconds. It fails at `TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS`, **not** the old
600-second deadline. The original failure binds the 949-byte planning input and reaped child;
its incomplete-attempt record contains no generated prefix or exact final token count. All 112
original files and cleanup checks pass their independent review, but no graph or peer task was
enrolled. Whether syntax-prefix exhaustion or complete-output rejection caused the decoder
failure cannot be established from the retained artifact. B03 remains incomplete.

A separate pure reproduction finds a real dead prefix: at 511 UTF-8 bytes a question can
have only one possible ending, `?`, which would duplicate the goal or an earlier question.
The decoder now rejects the character that would enter that state, preserving the existing
512-byte boundary, model-selected alternatives and exact original text. ASCII, Unicode,
JSON escapes and sibling-state regressions pass. A distinct fixed `TASK_GRAPH_DECODER_REJECTED_EOS`
code also separates complete-syntax EOS rejection from an empty parser-prefix set, without
retaining generated text. All 111 pure decoder/worker checks and three focused Rust diagnostic
checks pass. This repairs the reproduced source bug; only a new real run can establish its
effect on planning. No original failed run is relabeled as successful.

The [run on `682bdc27`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35856466271)
gets past the earlier empty-decoder failure, but consumes all 384 generation tokens without
completing a graph. The original diagnostic binds one rejected attempt, 391 prompt tokens,
1,642 output bytes by hash, and `TASK_GRAPH_GENERATION_LIMIT_REACHED` at 412.709 seconds.
Its generated text is not retained, so no particular question or semantic cause is inferred.
All 112 original files, worker isolation, cleanup and unchanged host bytes check out; no peer
task or usable graph was enrolled. The next candidate asks for concise questions and bounds
**generation only** to 192 UTF-8 bytes per question, leaving the full 512-byte admission format
unchanged. The model still chooses the tasks and dependencies; nothing is repaired or supplied
after generation. The schema, Unicode/prefix rules and reported generation limit agree, and
the 384-token, 896-context-token and 600-second budgets are unchanged. Twelve Rust graph checks,
36 pure decoder checks, 14 focused worker checks and the inert fixture check pass. This gives
the full JSON more room within its budget; real completion and B03 remain unproved.

The [compact-generation run on `d3a86b56`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35859759653)
now produces a complete original 808-byte graph in 213 generated tokens / 198.290 seconds.
Four model-selected tasks and dependencies are translated into five nodes including the
original-question terminal join. The retained result records five completed EOS answers.
The overall run still fails: the fixture writes its exclusive aggregate worker-observation
file again on the next polling iteration, raising `FileExistsError`. Only the first two live
worker observations survive, so full observation and original-free offline replay remain
unproved. The correction writes that aggregate once when observation ends, preserving each
original worker record. The dependency reader also compared Rust's fixed field order with a
key-sorted reserialization; it now binds the actual canonical parent bytes and their hashes.
Both inert fixture modes pass. The corrected reader validates the five jobs against all 114
retained original raw files; that retrospective check does not replace the missing live gates.
The actual questions and answers also contain incorrect routing
claims; executable task cooperation is not sound decomposition or answer quality. B03 stays open.

The [observation follow-up on `7ac8a154`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35863165144)
**passes its complete scoped execution proof**. Source-exact checking of all 140 original files
verifies the actual 808-byte model graph (213 generated tokens, 201.694 seconds), five live
isolated peer workers, original signed receipts and byte-exact dependent inputs. All five answers
reach EOS. After the original planner input is removed and the brokers stop, completed offline
resume performs zero new rounds and preserves the 114-file original snapshot. Protected-path
captures, private-store cleanup, zero remaining owned network objects and unchanged host bytes
pass. The model still misstates Route A as direct-exit and treats client-address disclosure as
satisfying privacy. This verifies model-selected task execution and retained-result recovery,
not useful reasoning, private offload, model-selected tools, complete B03 or the full alpha.

The [policy run on `b80f0b02`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35849851694)
now preserves the strict `PRINCIPLE_OUTPUT_REASONING` failure from both actual assessors.
Both reached a parsed response but no accepted judgment, cross-review or portable bundle;
their failed receipts retained 549/552 seconds of the original lease. All 126 original files
remain source-bound and unchanged. Raw rejected output is absent, so the exact reason-count,
field, principle-membership or duplicate-principle branch cannot be identified from this run.
Source review separately identifies an actual gap: the decoder permits repeated principles
that the independent validator already rejects. The next candidate constrains only that
uniqueness, leaving all fourteen initial choices, reasoning and outcomes to the model, and
keeps separate fixed failure codes for the four rejection classes. Known impossible Unicode
escape prefixes in graph questions are also excluded without repairing questions or adding
dependencies. All 116 pure Python checks and six focused Rust diagnostic/bootstrap checks pass;
the CLI compiles with the updated embedded worker. No model/backend runs on the development
host. These corrections are not evidence of real-model completion; B03/B06 stay open.

The [graph run on `c9b784a1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35673084743)
confirms real worker startup with the split-argument bootstrap, but **fails at `compute_deadline`**
after the baseline phase. Its original 600-second owner budget is unchanged; the artifact retains
neither generation progress nor the precise decoder subphase. No graph or peer work is proved.
The concurrent [policy run](https://github.com/VOLPAROSSA/volparossa/actions/runs/35673089855)
observes both real workers reaching baseline, then `TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS`, with
546/549 seconds still left at their failed receipts. No output or token count survives, so a
prefix failure cannot be distinguished from complete-output rejection. Original source-bound
reviews of all 110 graph and 126 policy files verify cleanup and unchanged host bytes; they
do not convert either run into a success. B03 and B06 remain incomplete.

The follow-up removes speculative graph-state cloning for every alphabet character at every
token-trie prefix. A direct membership predicate and immutable per-prefix cache preserve the
same graph transitions, including UTF-8 limits, escaped questions and required dependencies;
token/deadline budgets and the model's question/edge choices are unchanged. This addresses an
expensive decoder path found in source review, not a proven explanation of all the deadline's
elapsed time. Principle generation now distinguishes an incomplete JSON prefix from a complete
but invalid response: the latter returns its original strict validator code, without repair,
content logging or an invented EOS. This does not establish why the preceding run had no allowed
tokens. All 110 pure worker/decoder/principle tests pass, without executing the model or pinned
backend on the development host. Real completion still requires new disposable-VM evidence.

The [graph-v3 run on `2a565506`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35671611820)
**fails before the worker starts**: the original enrollment error is `compute_sandbox_spawn`
with `Argument list too long (os error 7)`. Exact source reconstruction yields a 136,410-byte
single Python argument, exceeding Linux's individual-argument bound. All 109 original files
remain unchanged; provisioning, cleanup and unchanged host-state checks pass, but no graph-v3
model behavior or peer execution is established. The concurrent
[policy run on the same source](https://github.com/VOLPAROSSA/volparossa/actions/runs/35671618254)
also fails before observed worker execution: both brokers record `supervisor_unknown`, both
assessment jobs fail, and cross-reviews do not start. Its artifact does not retain the OS error;
the common bootstrap problem is a possible explanation, not independently proved policy evidence.

The bootstrap correction splits only the fixed, compiled-in Python source into UTF-8-safe
32-KiB arguments and reassembles the identical source inside the existing isolated interpreter.
No files, mounts, shell, network access or task-controlled executable code are added. Private
inputs remain outside argv. Local diagnostics also preserve the fixed `compute_sandbox_spawn`
category without exposing arbitrary exception text. Three focused sandbox tests (including an
actual inert, standard-library-only >128-KiB Python bootstrap), three diagnostic tests and scoped
strict CLI Clippy pass. This proves the corrected argument handoff, not real-model success;
both complete disposable-VM workflows still require a new run.

The [graph run on `7309b266`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35663652657)
now produces a valid model-selected plan after one `GRAPH_GOAL_COPY` correction (55 + 52 tokens).
It chooses only one source question, without an internal dependency. The unchanged
`MODEL_TASK_GRAPH_INTERNAL_EDGE_NOT_PROVEN` gate therefore **fails** before peer execution:
valid JSON and enrollment are not the requested dependent-workflow proof. Its 110 original
files retain the exact proposal, input and report; original worker cleanup and host-state checks pass.

Dependent analysis is now an explicit owner request: `--plan-task-graph --plan-structure dependent`
binds `plan_requirement: dependent_analysis_v1` into the original input and report. Only that
request requires at least two model-selected tasks and an internal dependency; the normal
one-to-four-task contract remains unchanged. The worker explains the requirement and uses bounded
correction feedback without inserting questions or edges. The updated disposable graph fixture
uses a new, clearly synthetic routing-privacy case with concrete constraints and missing performance
measurements, rather than the earlier README introduction. Historical runs above remain failures;
this new request still needs real-model and peer-execution evidence.
Verification: 22 task-plan and ten graph-planner Rust checks, 95 pure worker/decoder checks,
scoped strict CLI Clippy, both fixture checkers and the compiled inert CLI smoke pass. The CLI
rejects the dependent option outside graph planning, before acquiring source or runtime state.

The [explicit dependent run on `28e96eab`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35669098540)
**fails before enrollment**. Two complete generated JSON objects are rejected as `GRAPH_GOAL_COPY`
(137 and 139 tokens, identical 539-byte hashes); the last 108 tokens exhaust the original 384-token
budget. Rejected text was not retained, so its questions, edges and the location of the copied goal
cannot be reconstructed from the hash. No graph or peer execution is proved. All 112 original files
are checked against the exact input, synthetic 444-byte source, requested dependency contract,
41-wheel provision, observed isolation, cleanup and unchanged host-state bytes. The next correction
must distinguish intermediate tasks from the original terminal question added by the coordinator;
the original no-copy rule and dependency proof have not been relaxed.

The new `model_task_graph_constrained_v3` candidate explicitly requests intermediate questions,
leaving the unchanged terminal goal to the coordinator. Its decoder blocks malformed question
endings, trim-equivalent goal/duplicate copies and invalid dependency indices during generation.
The requested dependent-analysis shape must be satisfied before a graph can close. The model still
chooses all questions, task count and valid edges; no answer or dependency is inserted to obtain a
pass. The supervisor and independent Rust/fixture readers recognize v3, while historical v1/v2
readers retain their original meaning. The original 512-prompt/384-total-token/four-attempt budget
is unchanged. Real-model execution and useful dependent cooperation remain unproven.
Verification: 24 task-plan Rust tests, 107 pure worker/decoder/principle tests, scoped strict CLI
Clippy, the compiled inert graph CLI smoke and both planning-fixture self-tests pass. No model
or pinned backend was executed on the development host.

The [first principle-assessment run on `db2f0776`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35663659331)
also **fails**: the original 128-byte public subject is fetched from its selected peer, and both
real 360M assessors run on distinct peers, but each reaches 256 generated tokens without EOS.
The incomplete schema-like outputs are not repaired or adopted. Neither cross-review starts;
the result remains incomplete/undetermined. Original cleanup and unchanged host state pass.
This is a model-output failure, not evidence of a failed content path or a peer memory-pressure event.

The [structured-decoder run on `ca766405`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35667596187)
also **fails**. Both distinct 360M peers execute, but their original outputs each reach 256 tokens
without EOS or a valid JSON boundary. They quote framework prose rather than the actual subject
and repeat a principle; more tokens alone would not validate those judgments. No cross-review,
portable bundle or completed offline replay is reached. Review of all 126 original exported files
checks the provider and content signatures, 41 pinned wheels, observed isolation, cleanup and
identical host-state bytes. A real cooperative pause/resume is observed on one worker; this is
not a worker-execution, transport or memory-pressure failure. The concept remains undetermined.

That structured candidate introduced an explicit signed public principle dataset v4 and fixed
assessment/review JSON decoding, not an outcome chosen by the coordinator. Owner-enabled
`--principle-inference-v4` brokers used the pinned optional decoder with the same 360M model,
one source row, 1024 prompt tokens and 256 generation tokens. Complete JSON has its
own `json_boundary` ending; it is not relabeled EOS. All source quotes, uncertainty and opposite
reviews remain independently checked. New enrollments are version 2; original version-1 jobs
keep their old document inputs and receipts. Real four-job success and B06 remain unproven until
the updated disposable fixture passes. No network-policy authority or activation is added.
Verification: 270 CLI compute checks, the additional v4 four-stage signed transfer/replay test,
seven content/protocol/agent admission checks, 91 pure worker/decoder checks, scoped strict Clippy,
the compiled inert CLI smoke and the static disposable-topology contract pass. These are not
evidence of usable real-model judgments, as the subsequent failed run above demonstrates.

The next generation candidate separates the unchanged framework from the exact untrusted subject
and review text. Its quote choices comprise every nonblank original-source substring up to 128
UTF-8 bytes, without choosing a principle or verdict for the model. Fixed field order asks for
evidence and reasoning before the outcome; all fourteen principles, three outcomes, counterarguments
and uncertainty remain available. The explicit generation-v3 envelope permits up to 512 answer tokens
for this structured task only. Ordinary inference and original generation-v2 receipts keep their
256-token contract. That candidate required completed output to fit 1024 bytes and pass independent source-grounding
and opposite-peer checks; no partial answer is repaired, accepted or relabeled EOS. This is a new
functional candidate, not a passing four-stage assessment or a claim of semantic reliability.
Verification: six generation-envelope tests, six coordinator/transfer tests, 102 pure worker/decoder
checks, scoped strict CLI Clippy, compiled inert policy CLI checks and the 56-negative-case fixture
self-test pass. The marked literal parser covers escaped quotes, backslashes, controls, Unicode and
literal whitespace; these checks do not execute the upstream decoder or model on the development host.

The [generation-v3 run on `729c9817`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35670300014)
**fails before any assessment is retained**. Two isolated workers reach the baseline phase, then
return failed jobs with no report/output and more than 550 seconds left before their respective
expiry. The broker records `worker_unknown`: its fixed diagnostic allowlist omitted the new
decoder/principle errors. The original exception code and any generated text/token count are not
recoverable; this is not evidence of a token-limit failure or a specific parser bug. The 126
original files verify source/dataset/custody bindings, 41-wheel provision, cleanup and unchanged
host-state bytes, but contain no complete judgments, cross-reviews or portable roundtrip. The
follow-up preserves only the existing literal decoder/principle error categories in local broker
diagnostics; arbitrary codes, source text and traceback content remain suppressed. This enables
the next diagnosis, not a retroactive explanation or a four-stage pass.

The next B06 transfer slice adds opt-in original provider-signed Poll transcripts, `policy-pack`
and `policy-fetch`. A completed four-stage public judgment can be packaged as an inert signed
native publication, retrieved through a fresh cache and reconstructed against independently
selected requester, assessor and subject keys. Every original challenge/request/reply signature,
exact source/context/dataset/report binding and opposite review is rechecked. Historical signatures
prove statements by keys, not truthful computation, trusted time, independent moral judgment or
policy authority. This candidate does not cure the model-output failure above; the real-model
four-stage/cache roundtrip remains unproven. No network-policy activation is introduced.
Verification for this slice: 268 CLI compute tests, six original-transcript tests, two local
protocol tests, two agent handoff tests, strict Clippy for the four affected crates and the
compiled CLI preview smoke pass. The four-stage transfer test uses real signatures over
explicitly synthetic reports; it proves binding/reconstruction and rejection, not model work.

The earlier `model_task_graph_constrained_v2` worker introduced a pinned, optional
LM Format Enforcer adapter that filters next-token choices to the JSON schema. The model still
chooses one to four questions and their dependencies; the original raw output is never repaired
or replaced. Independent graph validation and the original 512-prompt/384-total-token/four-attempt
budget remain in force. Parser failures cannot log a prefix or manufacture EOS. Source-bundled
adapter code runs only in the existing sandbox, and the three extra wheels require explicit
guest provisioning; ordinary inference/training retain the original 38-wheel runtime. Historical
v1 results remain readable without a decoder claim. The combined CLI passes 266 compute tests
and strict Clippy; 72 pure worker checks pass, with the preceding 10 decoder and 10 provisioning
checks unchanged. This is an
executable candidate, not a claim that the token-limit failure below is solved or that a
syntactically valid graph is a useful decomposition.

The [constrained graph run on `9d870440`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35661093770)
**fails** before enrollment with `TASK_GRAPH_ATTEMPTS_EXHAUSTED`. The real pinned decoder/model
uses 55, 147, 147 and 35 tokens: the first three complete JSON responses fail semantic graph
validation, and the fourth hits the remaining token limit. Rejected text was not exported;
the particular semantic defects cannot be inferred from the generic `INVALID_GRAPH` code.
All 112 original files are source-exact checked, including pinned decoder dependencies, actual
owner isolation, 6-GiB/four-vCPU guest, reaping, cleanup and unchanged host state. No peer job
or offline replay is reached, so this also does not prove the earlier peer-memory-pressure
problem resolved. Specific bounded rejection feedback is now added without repairing output,
supplying task contents or increasing generation budgets.

New B06 candidate: `compute peer policy-assess` fetches one exact signed public native text,
executes two selected peers' principle-led assessments and opposite-peer reviews, and derives
a scoped concept outcome with original receipts and preserved uncertainty/disagreement.
It uses all fourteen Latin principles as its reasoning framework, not the historical examples
as a classifier. Nine focused Rust checks and a compiled-CLI inert-preview smoke pass. A real
four-job disposable test is wired but not yet passed. No threshold signing, network-policy
activation, legal correctness, independent model judgment or full B06 completion is claimed.
See [scope and usage](DECENTRALIZED_AGENTS.md#public-principle-assessments-and-cross-review).

Latest real-model results remain failures, not completed agent cooperation. The
[model-selected graph run on `7de9448a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35656629758)
uses all 384 generation tokens without accepting a graph; no plan or peer tasks are enrolled.
The rejected text was not exported, so its contents are not inferred from the failure code.
The [two-subquestion run on the same source](https://github.com/VOLPAROSSA/volparossa/actions/runs/35656789632)
records `compute_memory_pressure` for one provider; the decisive memory sample is absent, so
low headroom and an unavailable measurement cannot be distinguished. The other provider executes
but reaches its 256-token limit without EOS. Neither run proves a completed join or offline
replay. Their original artifacts remain unchanged; private/network cleanup and identical host
state pass. These failures are separate from the subsequent import-checkpoint improvement.

The three fixtures that co-locate two 360M providers now select a 6-GiB disposable VM instead
of 4 GiB, with a read-only host headroom preflight. Other fixtures remain at 4 GiB; four vCPUs,
the per-worker 3-GiB RSS limit, 512-MiB spare-memory guard, threads and deadlines are unchanged.
Static contract checks pass. This is a fixture-capacity candidate, not a verified cure for the
observed cancellation, and cannot fix the independent generation-limit failures.

New local-private execution candidate: `compute private-task` reads a strictly separate
private question/context file, snapshots it into an owned ephemeral job tree and runs the
existing isolated CPU backend with owner-priority controls. It has no publication, training,
adapter, cache or peer-job path. Public admission still rejects the private format. Input is
not truncated; one context must fit the selected model's actual tokenizer budget. Temporary
input/report deletion follows confirmed worker reaping and precedes answer stdout, while the
original owner file remains untouched. Unconfirmed cleanup emits no answer and retains only
the owned job tree. Partial/non-EOS answers cannot become complete outputs. Five focused Rust
checks and 70 pure worker checks pass; live model/guest proof now passes as recorded below. This supplies a
local privacy fallback, not confidential distributed execution, larger private-document task
graphs, private training or B04 completion. A standalone `agent-private-task` KVM scenario now
checks a real pinned 360M answer to an authorized synthetic private note, observed readonly
snapshot/model mounts, owner acknowledgements and cleanup at the first stdout read. It also
requires the public executor to reject that private input before acquiring the runtime. Pure
fixture and static workflow checks pass. Only selected proof and
the explicitly synthetic test answer may be exported, never a user's private input or internal
worker report. See [usage](DECENTRALIZED_AGENTS.md#local-only-private-questions).
The [first private run on `75dcc9ad`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35660153750)
executes the actual 360M worker, returns the generated synthetic identifier with EOS after
12 tokens, and records cleanup and unchanged host state. Its overall check nevertheless fails:
the cleanup tracker aliased the embedded observed-process list and appended the same identities
again, so the final bundle disagrees with the separate original isolation record. The fixture
now copies that list before tracking cleanup; neither the original artifacts nor the strict
bundle-equality check are changed.
The [fresh run on `9d870440`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35661083371)
**passes**, including a source-exact check of all 15 original exported files. The actual pinned
360M worker returns the new synthetic identifier with EOS after 12 tokens. Independent private
snapshot, readonly mounts, network isolation, public-path rejection before runtime acquisition,
owner acknowledgements, worker reaping and temporary removal before first stdout all pass.
Original owner input stays intact; guest roots are removed without fallback signals and host
network-state bytes remain identical. The original failed run remains failed and unchanged.
This verifies the bounded local private lane, not confidential distributed computation,
private training, general answer accuracy or full B04.

Current dependency-ready candidate: a single incremental provider queue now owns source and
derived graph work. Each durable package completion triggers a dependency scan; newly ready
tasks join that same queue while unrelated original worker leases remain occupied. Workflow
locks survive until all admitted futures are drained, including preparation failures and
cancellation. Source identity/expiry, signed parent inputs and zero-round offline reconstruction
retain their existing contracts. Forty-nine focused document checks, nine cohort checks and
strict CLI Clippy pass. A disposable five-node A→C, B→D, C+D→E fixture is ready to observe
C completing while an actual B worker is paused under its original lease. **That live proof is
pending**; this is neither verified fully dynamic scheduling nor completion of B03.
The [first run on `c0e692a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35629187398)
fails at `READY_DAG_C_DID_NOT_FINISH_BEFORE_B`: the exact paused B worker disappeared.
The retained startup observation precedes any owner-control acknowledgement. Pausing there
can trigger the existing ten-second acknowledgement deadline; the original terminal reason
was not exported, so that mechanism is a source-backed diagnosis, not a captured verdict.
All five tasks eventually completed in six rounds with a replacement B, but that does not
prove C finished while the original B remained occupied. The 119 original files verify initial
worker overlap and cleanup/unchanged host state, not the required dependency-ready boundary.
The [startup-corrected run on
`059b4a71`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35632573848) also fails: its
120 unchanged original files prove the exact startup ACK and baseline before B was stopped,
but the original worker/owner guard later fails without a retained terminal reason. All five
tasks again complete with a replacement B, not the required original-lease boundary; cleanup
and unchanged host state pass. `SIGSTOP` prevents any later control ACK, not only startup, so
it is unsuitable for this fixture even though that is not a captured verdict on the old failure.
The new disposable fixture uses a B-only, explicitly injected CPU-pressure floor in its private
mount namespace to request a real cooperative Pause. It requires the original worker's ACK,
then restores the original pressure view and waits for Resume under the unchanged lease and
normal quiet-time guard. No actual CPU-load measurement or speedup is claimed from this injection.
Ordinary inference now services owner controls between generated tokens and after generation,
rather than only before an entire output. Its existing token budget, cancellation, original
deadline and control-acknowledgement limit remain unchanged. The 44 pure worker protocol checks
pass; this updated dependency-ready scenario still needs its own live proof.
Backend preparation also checks the same control pipe between its individual imports and
configuration steps, always on the execution thread after the preceding operation returns.
Two real-pipe tests with inert import doubles verify pause acknowledgement/resume gating and
cancellation before the next import; all 64 current pure worker tests pass. An individual
native import remains non-preemptible. This improves checkpoint granularity, without claiming
that it explains or fixes the observed VM worker failures or completes owner-priority acceptance.
Its [run on `66abf863`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35641415889)
fails before pressure injection: the helper rejects the runner's actual
`/opt/va.<32-lowercase-hex>.<6-mktemp-characters>` work directory because its old expression
accepts only one dot. Original workers, overlap and startup acknowledgement are observed;
cooperative Pause, C-before-B and restored pressure are not proved. Network cleanup and
unchanged host state pass, but the private-cleanup record is missing. The helper now accepts
the exact runner layout, retaining all original KVM/root/ownership checks. Three valid path
shapes and 33 negative path/pressure/isolation/restoration controls pass without executing
mounts or namespaces; the corrected scenario still needs a fresh live run.
Its [run on `066f46de`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35644724074)
passes that work-directory guard but rejects a CPU-covering mount with shared propagation,
before creating the pressure source, plan or bind mount. Review of 119 unchanged original
files verifies both original workers, overlap and B's startup acknowledgement, plus process,
private-state and network cleanup and unchanged host state. It does not identify which broker
or mount failed, and does not prove cooperative Pause or C-before-B under the original lease.
The fixture now retains a bounded, root-private isolation record before that unchanged guard:
guest and original broker identities, mount namespaces, CPU file identities and exact relevant
mountinfo lines, including propagation fields and the first shared-mount rejection. The guard
uses those same observed bytes; diagnostics do not permit a previously forbidden mount.
Existing failure export retains this record even without a pressure plan. Pure parser, record,
size-limit and rejection checks pass alongside the existing helper controls; live diagnosis and
the required dependency-ready proof remain pending.
The [diagnostic run on `750420e2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35649817352)
identifies relay4's root mount as the first rejection (`shared:1923 master:1`); its `/proc`
is also shared/slave, as are relay5's mounts with different peer-group IDs. Both brokers have
distinct mount namespaces, but that alone does not meet this fixture's nonshared-mount guard.
The record confirms no pressure source or bind mount was created; cleanup and unchanged host
state pass. This is not evidence that outward propagation or host modification occurred.
For this disposable scenario only, broker units now select `MountFlags=private` alongside
their existing sandbox settings. Systemd 257 otherwise finishes `PrivateMounts` setup with
shared propagation after first making mounts slave; see its [execution documentation](https://github.com/systemd/systemd/blob/v257/man/systemd.exec.xml#L2182).
The original mount guard still verifies actual topology before injection. No production unit
or host mount is changed; other scenarios retain systemd's shared default. The private setting
also stops incoming mount events, so it is limited to these short-lived, fully torn-down units.
The updated fixture still requires a fresh live run.
The [combined 360M run on `b4eaa670`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35651954279)
fails earlier, while waiting for the two initial source workers to overlap. The owner's final
summary reports five EOS answers, but assigns A and B successively to relay4; relay5's log
contains an initial worker that reaches `preparing` without a corresponding baseline/complete.
The retained files do not establish why that attempt ended. No pressure injection or private
mount verification was reached, so this does not prove or refute the mount correction.
All 117 original files remain unchanged; private/network cleanup and identical host state pass.
Initial concurrency, C while the same B remains paused, and full receipt/offline proof remain open.
Those two early observer failures now export a separate bounded failure snapshot before the
unchanged failure/cleanup path. It retains original job/state/receipt bytes, including retries,
with file identities and observed concurrent changes. The record explicitly denies success,
quiescence and coherent-snapshot proof; success checks still reject replacement attempts.
Only the prepared public README fixture tree is included, never model/runtime/key/cache
directories. Pure diagnostic controls and shell checks pass; the original attempt's cause still
requires a new live observation, not an inference from this added diagnostic code.
The [diagnostic run on `0e27c806`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35655335733)
retains 116 original raw files: A and B initially used different providers, but B failed before
expiry and a later follow window retried it on A's provider. Five tasks eventually yielded EOS
reports, without proving the required original-live-B boundary, pressure injection or offline
replay. This explains the eventual shared-provider assignment without demonstrating an initial
allocation bug. All 119 exported files remain unchanged; private/network cleanup and equal
host bytes pass. The underlying worker cause remains unknown on this pre-classification source.
The combined candidate keeps that single dynamic queue while integrating the 360M profile and
actual generation-end contract. Source and derived frontiers retain the enrolled profile;
terminal empty, wire-truncated, token-limited or generation-unknown answers cannot create new
dependencies or a busy follow loop. Unrelated admitted work retains its original lease until
completion/drain. The updated five-node fixture selects 360M explicitly without changing its
source, questions, dependency graph, pressure guard or original-worker proof. Its live result
is still pending; the diagnostic run on `750420e2` tests the preceding 135M snapshot only.
The combined tree passes 235 focused CLI compute tests, 53 pure worker protocol tests, strict
CLI Clippy and the targeted ready-DAG/model-planning/successor fixture, shell and KVM-contract
checks. These do not execute the integrated model/peer workflow or establish answer quality.

Current model-planning candidate: `compute peer document --plan-tasks --public-question`
runs an isolated pinned model to propose two public subquestions. Strictly validated
question data forms a fixed fork/join graph, with the original user question unchanged in the
terminal join. New planning includes the exact UTF-8 prefix of the selected public source,
at most 1024 bytes, alongside its original full-source hash and size. The versioned input,
report and graph authority bind that prefix's byte range and digest, explicitly distinguishing
complete from partial source coverage. Receiving this text does not prove understanding or
useful decomposition. Source acquisition occurs once, and the exact planner
input, report, artifact and enrollment hashes are checked on resume without replanning. Invalid
output may be regenerated within the same bounded invocation; exhausted budgets fail without
a repaired/canned plan, tool authority or private offload.
The initial implementation passed forty-eight focused Rust checks, twenty-nine pure Python
protocol tests and strict CLI Clippy. The [first real run on
`086761c`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35619669855) **failed** at
`TASK_PLAN_GENERATION_LIMIT_REACHED`: an actual isolated pinned-model worker reached the fixed
384-new-token limit before any plan was accepted. No peer task started. The 109 original
artifact files retain the real worker observation and successful cleanup/unchanged host state;
the generated token sequence was not retained, so its text and reason for continuing are unknown.
The shorter prompt and whole-JSON stop passed eight focused Rust checks, thirty-two pure Python
checks and strict CLI Clippy, but [actual run `845b1c0`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35622327797)
**failed at the same generation limit**, before a plan or peer job. Its 109 original files
verify actual owner isolation and complete cleanup/unchanged host state, not generated text.
The next candidate separates task content from serialization: two successive model-generated
questions, with the first included while generating the second, and a locally supplied JSON
structure. Each stage has fewer than 192 new tokens (combined below 384), at most 512 prompt
tokens and the same original owner deadline. Exact question text, per-stage stop reasons and
counts remain bound to the original report. No canned questions, model-selected task count,
complete model/peer/offline-resume proof or answer-quality claim; B03 remains incomplete.
Eight focused Rust checks, thirty-three pure worker tests, the fixture's pure checks and strict
CLI Clippy pass; the two-question strategy still needs its actual isolated model/peer proof.
The [two-question run on `14b91c0`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35625031280)
**failed before enrollment** with `UNKNOWN_FIXED_FAILURE`; no accepted plan or peer phase is
proved. The new `QUESTION_1`/`QUESTION_2` diagnostic prefixes contain digits, but the existing
supervisor admits only uppercase letters and underscores. They are corrected to `QUESTION_ONE`
and `QUESTION_TWO`, with cross-language contract checks; generation and budgets are unchanged.
The original unfiltered failure reply was not retained, so its precise stage/cause remains unknown.
The [diagnostic-corrected run on `809497b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35627888279)
**fails at `TASK_PLAN_QUESTION_TWO_INVALID_TEXT`**, before enrollment or peer execution.
The final second-question text check was reached after token/framing checks; it rejects empty,
over-512-byte, NUL-containing or non-UTF-8-encodable text. Its exact condition is unknown because
the original output text/tokens were not exported. Source-exact review preserves all 109 original
artifact files and verifies actual owner isolation, pause/resume and complete cleanup/unchanged
host state, not a valid model plan, peer graph, offline resume or answer quality.

The earlier recovery candidate uses `model_questions_scaffold_recovery_v2`: at most four
generations under the same original owner deadline and 384-token total allowance. Each
generation receives at most 192 new tokens or the smaller remaining allowance. Rejected tokens
count too; two accepted questions are required before that total is exhausted. Only empty,
overlong, NUL-containing, duplicate or token-limit output may trigger another generation, using
fixed categorical feedback rather than repaired text or replacement questions. Backend,
encoding, framing, cancellation and other integrity failures remain fatal. Exact accepted text
is bound to all attempt metadata; failure diagnostics retain only counts, fixed reasons and
text hashes after child cleanup, not rejected text or enrollment authority. Resume never
replans. Twenty-six focused Rust tests, thirty-nine pure worker tests, the fixture's pure
checks and strict CLI Clippy pass. Its [actual run on
`3afd45db5`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35632214835) and source-exact
review of 137 unchanged original files **pass mechanically**: four charged generations use
380 tokens; three real peer workers execute the enrolled graph; completed offline resume
uses zero rounds and preserves the original history. Protected captures, full cleanup and
unchanged host state pass. However, the accepted texts describe an unrelated electric-vehicle
energy-storage project, are not useful VOLPAROSSA subquestions, and one echoes a shortening
instruction. This is a concrete semantic shortfall, not successful task decomposition.

The preceding `model_questions_source_recovery_v3` candidate supplies the actual public source prefix
and requires the entire accepted output to end in `?`, including EOS completions. A bounded
`NOT_A_QUESTION` rejection can trigger another charged attempt; there is no question extraction,
text repair or canned fallback. Four attempts, 512 prompt tokens, the shared 384 generated-token
budget and original owner deadline are unchanged. The next disposable fixture uses the full
literal README introduction before its navigation, rather than a truncated 128-byte slogan,
with the same original question. Tokenized peer work is counted from actual retained plans,
not assumed to fit three jobs. The [source-grounded run on
`bebbc8ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35638510308) and source-exact
reconstruction of 137 original files pass mechanically: the literal 506-byte introduction feeds
two generations using 45 tokens, followed by three actual peer workers and unchanged zero-round
offline resume. Protected captures, full cleanup and unchanged host state pass. Content review
still finds concrete failures: the first question repeats the original goal, and a peer answer
and the final join invent an OpenVPN dependency absent from the source. All three peer answers
hit the 64-token limit mid-sentence; their `text_truncated=false` reports only the separate wire
text cap, not generation completeness. These are unresolved usefulness/completeness gaps,
not a verified source-faithful answer or a complete task decomposition.
Seventeen focused Rust tests, forty-two pure worker protocol tests, the updated fixture's
pure controls, shell checks and strict CLI Clippy pass for this source-grounded change.

The current answer-path correction adds actual token-level `generation` termination metadata:
`eos` or `token_limit`, with a version and the unchanged 64-token profile bound. An EOS at the
last permitted token remains EOS, not an inferred token-limit stop. New local inference and
training reports require this contract; old receipts without it remain generation-unknown.
Terminal job execution stays terminal, with no implicit resubmission or lease extension.
Public task/document results distinguish execution completion from usable output, and new
dependency/synthesis work requires nonempty, non-wire-truncated EOS output. Retained historical
report/parent/result bytes stay unchanged rather than acquiring invented metadata. EOS alone
does not prove correct, relevant or semantically complete answers. The 212 focused CLI compute
tests, 47 pure worker protocol tests and seven targeted pure fixture checks pass. These checks
do not execute a model; the updated termination contract still needs live execution. No new
model-quality or complete-alpha claim is made.

The next executable candidate adds explicit `smollm2-360m-v1` selection across guest-only
provisioning, the isolated worker, broker capabilities, discovery/manual peer enrollment,
task/document planning, resumed receipts and derived synthesis. It pins the original 360M
revision and complete assets, permits one ordinary inference row with a 1,024-token prompt,
256 generated tokens and 4,096 escaped output bytes, and refuses 135M adapters/training.
The 135M default, historical encodings and training path remain unchanged. New enrollment
pins a common exact model fingerprint even with manual peers; resume cannot substitute a
different profile. Signed four-row packages are dispatched as singleton jobs. Complete parent
answers are retained with the matching profile; no shortened parent or smaller-model fallback
is introduced. Existing CPU/RSS/deadline limits and separate task-planner budgets stay fixed.
Compilation, strict Clippy for the four changed crates, 215 CLI compute tests, eleven focused
content/control/agent profile tests, 53 pure worker tests, seven provisioning tests, the
targeted pure integration helpers and shell/KVM-contract checks pass. They are local evidence
only, not model execution. The updated disposable
`agent-model-planning` [run on `c67e4906`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35648922086)
executes the pinned 360M planner and enrolls its actual two questions, but fails before peer
execution: the fixture supplies both `--resume` and `--model-profile`, which the CLI correctly
rejects. Resume must retain the enrolled profile, not select it again. The fixture now omits
that redundant flag on peer execution, as it already did for completed offline replay. The
first generated question still exactly repeats the original user question; the second asks
about risks and benefits of decentralized user-operated networks and their mitigation. These
texts do not establish useful decomposition. The complete 360M peer workflow, offline replay
and answer-quality review remain pending; no performance, full B03 or alpha claim is made.
Source-exact review of all 125 unchanged original files verifies pinned provision, the actual
isolated planner, 37 generated tokens in two question-boundary completions, signed-source
lineage and exact enrollment. Worker/private/network cleanup and identical host bytes pass.
The run admits zero peer jobs; its sixteen captured packets are not a complete datapath proof.
The corrected-fixture [run on `8232944f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35651436847)
stops during pinned model provisioning with a connection reset, before any planner or peer job.
Its thirteen original files retain that failure and passing private/network cleanup with
unchanged host state. It therefore provides no new evidence for the corrected resume command
or the complete model workflow; the original failed artifact remains unchanged.

The new `model_questions_source_recovery_v4` asks for narrower subquestions and rejects an
exact UTF-8 copy of the original user question as `GOAL_COPY`, after the normal question/EOS
boundary. Every rejection retains its actual token cost in the same four-attempt, 384-token
budget and original deadline. Successful reports bind the rejected hash and byte length to the
original input and cannot accept that exact text; historical v1–v3 reports remain readable.
No text normalization, semantic-equivalence detector, canned replacement question or larger
budget is introduced. All 239 CLI compute tests, 56 pure worker protocol tests and the updated
fixture's pure controls pass. The [actual v4 run on
`ab026329`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35653401923) rejects an exact
goal copy, then accepts two questions in three attempts and 39 total tokens. The first accepted
question paraphrases the goal, so useful decomposition is still not established. Both real
isolated peer workers start on different brokers, then return `Failed/worker_failed` well before
their original expiry; neither produces an answer and the dependent join does not run. The
128 unchanged original files prove pinned planning, tokenizer/source bindings and passing
private/network cleanup with identical host bytes, not a complete peer workflow. The old broker
discarded the detailed cause. A new local diagnostic emits only allowlisted fixed worker or
supervisor failure categories, never arbitrary error text or task data; external receipts,
retries and deadlines stay unchanged. All 17 focused broker checks pass. Memory pressure,
owner-control failure and backend failure remain hypotheses until a new execution identifies
the category; no resource limits have been increased to conceal the failure.

A separate `--plan-task-graph` candidate now connects model-selected task count and dependency
edges to the existing incremental executor. Input and raw artifact version 3 retain the same
public source binding; `model_task_graph_v1` proposes one to four tasks with earlier-index
dependencies. Rust preserves every selected question and edge, supplies stable IDs, and adds
only the unchanged original question as a terminal join of all model-selected terminal branches.
The existing two-question mode and historical replay remain unchanged. One owner retains the
512-prompt/384-total-generated-token budget across at most four whole-JSON attempts, charging
rejections without replacement tasks. Raw JSON is retained exactly, including whitespace.
All 245 focused CLI compute tests, 62 pure worker protocol tests and strict CLI Clippy pass.
The separate disposable `agent-model-task-graph` scenario now preserves the raw proposal and
requires at least two model-selected tasks and one internal dependency before checking real
peer execution, unchanged original-question synthesis and completed offline resume. Serial
graphs need not pretend to have simultaneous workers. Valid graphs without an internal edge
remain legal product output but cannot pass this particular proof. Pure fixture controls,
shell/YAML and the KVM contract checks pass; no graph is supplied to the live planner by those
tests. Live model-selected dependencies, peer execution and source-faithful answers are not
yet proved, and B03 remains incomplete.

Verified 135M learning-to-serving slice: an explicit shared `--serving-directory` connects the
training loop's selected approved local/peer successor to an already running peer-inference
broker. Publication binds the original approval, exact three adapter files, runtime and expiry;
idle-only activation copies those bytes into broker-owned bounded storage. Active work and old
receipts keep their original bindings. The agent attachment follows changing model fingerprints
only with an explicit broker capability, while preserving its socket, base-model and task-profile
checks. Static brokers retain their prior behavior. Expired/corrupt selections cannot become
base-model admission after restart; a retained valid copy stops at its original expiry.
Thirty-three focused storage, selection, broker, protocol and attachment checks plus strict
all-target CLI/agent/local-control Clippy pass; the actual trained-model/protected-peer-job
transition now has the source-exact VM proof below. This is not a B03/B05 completion or evidence
of general model improvement. The 360M inference-only profile rejects a successor-serving
directory and does not activate the incompatible 135M adapters.
See [usage and limits](DECENTRALIZED_AGENTS.md#using-approved-successors-for-new-peer-jobs).

The [first learning-to-serving run on
`98ce45bf`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35636907319) fails before
base-model inference or training. Its 115 unchanged original files show
`accepting_work=false`, followed by an immediate `compute_peer_busy` refusal before any job
handle or Submit RPC. The exact capacity constraint is not recorded. The fixture also parses
the runner's cleanup flag as `yes` instead of `true`; its original report therefore remains
failed despite independently recorded zero remaining objects and identical host-state hashes.
The correction waits within a fixed bound for the actual expected broker/model to admit work
and parses the runner's boolean without relaxing capacity, ownership or cleanup checks.
Training, activation and adapted peer inference still require a successful new execution.

The [readiness-corrected run on
`de3922b3`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35639387212) verifies actual
base-model peer inference and a 1,005-byte public-source fetch. It then records an unsuccessful
training-loop cycle before any training worker is observed. The missing `/proc` entry belongs
to the loop owner, not an identified training worker. Its 125 unchanged original files contain
no training report or specific cycle error, so they do not prove a worker crash, memory failure
or expired lease. Cleanup and unchanged host-state checks pass; the failed run lacks the final
selection records needed for full protected-path reconstruction.

Source inspection identifies a blocking fixture mismatch: its selected learner is relay-only,
but named-source retrieval requires the client role even for a complete local cache hit. The
correction enables client capability in that disposable learner's startup configuration, keeps
relay service enabled and validates its exact pre-provisioned source through the ordinary
cache-only API before training. It does not bypass the download ACL or claim learner-side
network acquisition. Training, approval and same-broker adapted inference still need live proof.
Pure fixture checks and shell syntax/ShellCheck pass. Failure cleanup now retains only bounded
fixed-file identities and cycle-state categories, not source text or arbitrary error chains.

The [role-corrected run on
`41911695`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35642406080) reaches the new
cache-only preflight with the correct learner roles, but returns `CONTENT_INVALID` before
training. No cycle is started. The fixture had copied the complete cache, including the owner
marker bound to its original directory's device, inode and UID; reopening the different copied
directory is correctly rejected. The fixture correction relocates the closed, same-owner cache
without changing its directory identity or bytes, an operation already supported by the store.
It never rewrites the marker or relaxes the product cache validation. The failed run's original
cleanup records prove removal of its observed workers/private stores and unchanged host state;
training, approval and activation remain unproved until a successful new run.
The four existing cache-reopen tests pass, including rename/reopen and copied-marker rejection;
the fixture's pure relocation checks, shell syntax and ShellCheck also pass. No model was run
by these checks.

The [corrected run on `4718cb1c`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35645297213)
and independent reconstruction of all 151 unchanged original files **pass**. The same broker
first serves a real base-model job, then follows eight actual training updates and local
approval to serve a new job using exactly those trained parameters from its own retained copy.
The original base-job receipt stays unchanged; invalid new selection metadata does not replace
the approved copy. Local held-out loss falls from 2.0890 to 1.2442 on only four target tokens:
this is not general answer-quality evidence. The fixture's same-filesystem cache relocation
retains inode, ownership marker and file hashes; the learner's source read is explicitly local,
not autonomous network acquisition. Full protected-path reconstruction, 28,968 captured frames
with zero drops/direct client-exit packets, worker/private/network cleanup and identical host
hashes pass. Quality/CodeQL pass, and PR #146 was normally merged as `c1e231d4`, whose tree is
identical to the tested head. Global model adoption, restart/expiry practice and full B05 remain open.
Integration of that milestone with the new 360M candidate retains old-model idempotent receipts,
limits dynamic successor activation to 135M, and keeps both disposable scenarios available.
The combined tree passes 226 CLI compute tests, four agent successor checks, twelve local-control
compute checks, strict targeted Clippy and the merged fixture's pure/static checks. The new
360M peer execution remains pending after the fixture CLI rejection described above; those
checks do not extend the historical 135M VM proof to it.

Verified public task graph: `compute peer document --task-plan` enrolls different
questions and explicit dependencies over the same selected public source or source collection.
Independent source tasks share the existing cross-package provider queue and the exact same
original signed source, validity and peer selection. Once source work completes, ordered
dependency frontiers consume receipt-reconstructed parent answers. Even a single-parent step
runs its own new instruction; it cannot return the parent's answer as if it performed new work.
Graph and per-node identities are retained, and completed replay preserves existing execution
summaries. Forty focused document tests and strict all-target CLI Clippy pass. The [four-node
run on `56a7c374`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35616745770) and replay of
all 138 unchanged original evidence files **pass**: two real initial workers finish under the
two-round boundary; comparison and single-parent refinement then each run a distinct worker.
Original input/plan removal and stopped brokers precede zero-round offline resume with unchanged
history. Five captures contain 33,052 frames with zero drops/direct client-to-exit packets;
private/network cleanup and unchanged host state pass. This verifies the explicitly enrolled plan.
That verified scheduler has a source-stage barrier and ordered dependent stages. The newer
dependency-ready candidate above is not covered by that proof. Neither result completes B03
or adds private computation or verified automatic task planning.

Verified mixed network-source execution: source-plan v2 combines explicitly selected local files and
native signed `text/plain` publications in the same public document task. Publisher key, name
and exact manifest ID are fixed before any cache lookup. Verified cached chunks are reused;
missing content is fetched through the existing protected content path, never replaced by a
different cached source. The owner retains original manifests and correlated local receipts,
authenticates their exact bytes on resume and caps compilation validity at the earliest original
source expiry. A publication signature is not a claim about authorship, licensing or answer truth.
Twenty-eight focused document tests and five public-text tests pass without model/network
execution. The [first mixed local/cache-hit/network-miss run on
`1faa76d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35612754648) **failed** after
sixteen actual worker jobs. Its original artifacts independently verify both native signatures,
one cache hit, one protected cache miss and nine completed source-fragment jobs, but not the
final synthesis or offline resume. Both executors retained eight terminal jobs until their
original expiry and consequently refused further admission. The corrective broker change
separates its unchanged single active worker from a bounded 256-record/32 MiB retained history,
including a worst-case space reservation for the next job. Original receipts and expiry remain
unchanged; thirteen focused broker tests pass. The [corrected run on
`dd405d9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35616445632) **also failed**, now
after eight completed fragment jobs: a new retained job handle remained unconfirmed with
`COMPUTE_RPC_UNCONFIRMED`, without a terminal receipt. Synthesis did not start. This is a
separate submission/confirmation failure under investigation. The later passing execution below
does not retrospectively resolve it or add automatic web research, private computation or B03.

The new diagnostic step preserves fixed RPC operation/category and an authenticated broker
error code when available, while leaving uncertain handles, slot ownership and original
deadlines unchanged. The disposable collection observer now samples only allowlisted RPC
boundary codes before they leave the in-memory log ring. These timestamp observations are
lower bounds, not task correlation or proof of a specific transport cause. Six focused queue
tests and the pure diagnostic parser checks pass. The [diagnostic run on
`87b166d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35621161591) **failed earlier**, at
the first native custody deposit. Original control-relay logs show an unavailable provider
address after its exact lookup; the client rejected the resulting incomplete target set.
No compute job was reached. This is not proof of an invalid signature and does not resolve
the previous unconfirmed submission. All 121 original artifact files were retained; cleanup
and unchanged host state passed. A follow-up adds fixed address-resolution failure categories
and early client/control-relay snapshots around deposits and warmup, without changing lookup
acceptance, timeouts, retries or authority. It is diagnostic, not a claimed functional fix.
The [run on `0faba056`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35624295193) and
source-exact reconstruction of all 174 original files **pass**: one local source, two exact
native publications and their original custody signatures, a real cache hit and protected cache
miss. Nine fragment jobs feed synthesis 9→5→3→2→1, twenty actual workers across two peers.
Original input/source-plan removal and stopped brokers precede zero-round offline resume with
identical retained receipts. Five captures contain 131,266 frames, zero drops/direct-exit packets;
complete cleanup and unchanged host state pass. This proves this mixed-source execution, not
answer quality or causal repair of the earlier intermittent address/submission failures.

Verified public-source collections: `compute peer document --source-plan` accepts
2–32 explicitly public local UTF-8 documents with absolute input paths and one explicitly
selected common license. It builds an owner-published compilation whose signed bytes bind
each source label, original hash, byte length and exact ranges. A separately pinned ledger
distinguishes original bytes from synthetic headers; result provenance describes input-byte
coverage, not semantic citations or authentication of the original publishers. Existing real
tokenization, shared peer queues and optional synthesis process the compilation. Resume uses
retained compilation bytes and receipts, without reopening the original input files. Completed
shared-queue synthesis also preserves its existing execution summaries instead of replacing
them with a zero-round resume summary. The 19 focused document tests, the dedicated completed-resume
regression and strict all-target CLI/agent Clippy pass. The [disposable run on
`e38b0c522`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35609419691) and reconstruction
of its 145 original evidence files pass: three public sources feed seven fragment jobs and
three real synthesis levels (4, 2, then 1 job), for fourteen actual isolated workers. Original
input files and the source plan are removed before zero-round offline resume with unchanged
receipts. Captures retain 70,144 frames with zero drops or direct client-to-exit packets;
private/network cleanup and unchanged host state pass. This verifies local-source collection
execution, not semantic answer quality, network-source retrieval or completion of B03.
See [source-plan format and usage](DECENTRALIZED_AGENTS.md#working-with-several-public-sources).

Verified single-package ready queue: new `compute peer workflow`, `task` and `document` enrollments
use `ready_rows_v1`. Within one signed source package, a free compatible peer receives the
next never-submitted row without waiting for other peers' running rows. Immutable queue plans
and exact per-row handles precede submissions; completed receipts are saved before slot reuse.
Resume preserves completed results, unconfirmed leases and the original source/model/expiry.
Already attempted rows use the existing lease-safe reconciliation path, not a new queue entry.
Retained histories without a scheduling field keep their grouped-batch contract; `--batch-barrier`
is an explicit enrollment-only compatibility option. All 138 focused CLI compute tests and strict
all-target CLI Clippy pass without loading a model. The `agent-jobs-ready-queue` disposable scenario
is wired through the guest, outer runner and CI; its pure positive/negative checker, script syntax,
YAML and existing non-mutating scenario contracts pass. The [live run on
`4b907e08`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35603301387) and reconstruction of
its unchanged original upload now **pass**: a free executor starts another real row while the
original worker is deliberately paused under the same owner and unexpired lease. Four ordered
results survive in one attempt; completed resume with both brokers stopped performs zero rounds
and changes no retained files. Six capture records cover 33,178 frames, with no capture drops or
forbidden direct client-to-exit packets. Private/network cleanup and unchanged host-state checks
pass. The pause is disposable-fixture orchestration, not product scheduling behavior. This is
execution/retention evidence, not measured speedup, answer quality or full B03.

Verified cross-package queue: several independently signed packages now share one bounded
provider registry and source-aware round-robin queue. New rows from another admitted package
can use a freed peer without waiting for the first package to finish. Original source/model/expiry,
per-package plans, handles and receipts remain separate; uncertain leases reserve capacity even
outside the current admission window. The document and synthesis frontends use the same queue in
groups of at most 32 packages, within the explicit per-window package-attempt budget. Larger groups
and dependent synthesis stages remain sequential; eligible failed-row retries still use the existing
stopped/expired-job path after the fresh-row queue drains. The `agent-jobs-package-queue` disposable
scenario requires real A0/B0/A1/B1 execution across two signed packages, overlap with the original
paused worker, original receipts, no-work completed resume and full cleanup. The [live run on
`46e5b14`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35606034707) and reconstruction of
its 136 unchanged original evidence files **pass**: with A0 paused under its original pidfd-bound
worker and lease, the free peer completes B0, then A1, then executes B1. All four actual jobs
retain their source-specific results; completed offline resume performs zero rounds and changes
no receipts. Six captures cover 32,731 frames with zero drops or forbidden direct-exit packets;
private/network cleanup and unchanged host-state checks pass. All 147 focused CLI compute tests,
strict all-target CLI Clippy and the fixture's pure positive/12-negative checks also pass.
This proves cross-package refill and retention, not comparative throughput, answer quality,
general task planning or full B03.

The corrected executor-discovery checkpoints on `8a21d43d` now **pass**: the
[document/synthesis run](https://github.com/VOLPAROSSA/volparossa/actions/runs/35600666064)
and [third-peer recovery run](https://github.com/VOLPAROSSA/volparossa/actions/runs/35600672677)
were reconstructed from their unchanged original uploads with source-exact checkers. The document
artifact retains all eight previously missing discovery files and proves the real
`10 -> 5 -> 3 -> 2 -> 1` inference chain; 92,786 captured frames show no forbidden direct
client-to-exit packets or drops. Recovery preserves completed work and executes the missing row
on an actual third peer under the same owner, with two attempts and admission before submission;
44,982 captured frames likewise pass. Both private/network cleanup checks and unchanged host-state
checks pass. Quality and CodeQL on this head also pass. These are scoped execution/recovery
proofs, not answer-quality evidence or completion of B03. Earlier failed runs stay failed.

Current executor-discovery candidate: `compute peer workflow`, `task` and `document` accept
`--discover-peers` in place of manually supplied provider keys. Authenticated, protected probes
check actual broker availability, supported inference profiles and permission for the explicitly
selected public-source publishers. The coordinator selects two through four compatible peers
with one exact model fingerprint and durably pins that selection before submitting work.
Resume retains the original selection and model; additional peers require replacement permission
recorded at enrollment. A fresh capability check cannot silently change the model.
Discovery contains no prompt or source body and does not admit a worker. Source choice remains
independent of cache availability. `document --enroll-only --execute` explicitly separates this
preparation from later execution. The [first automatic-discovery run on
`a65a3242`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34916523136) **failed** during
executor enrollment with `CONTENT_UNAVAILABLE`, before any peer job or synthesis. Its retained
logs show provider offers and two completed protected flows, but no retained capability/budget
replies explain why no eligible cohort was selected. Final route/policy rejection would produce
`CONTENT_POLICY`, not the observed code; offer expiry also does not fit the observed startup
timing. Temporary startup readiness remains a hypothesis, not a proven cause. Cleanup completed
with zero owned objects and unchanged guest-host state. Exact-head Quality and CodeQL passed; they do not turn the live run
green. The corrected live automatic-selection proof is recorded above.

The [follow-up document run on `66b70e3d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35597171441)
also **failed**, this time at the post-run evidence check. The guest completed automatic
enrollment, document execution and four synthesis levels, with cleanup and unchanged host
state reported. Independent replay of the unchanged uploaded artifact cannot verify the
discovery path: eight original discovery-capture files were not exported. Embedded summaries
do not replace those originals. The finalizer now exports both bounded executor-discovery
JSON prefixes alongside the existing execution evidence; a local export regression exercises
the actual shell function, checks byte retention and private permissions, and excludes symlinks
and unrelated private files. The historical run remains failed; complete live evidence from
the corrected source is recorded above.

Discovery now retries temporary unavailable/busy observations with fresh offers and nonces,
within one original 150-second deadline. Fixed diagnostic categories separate query, probe,
readiness and final-check failures without storing publisher identities or task bodies.
Policy/protocol failures are not converted into readiness waits.

The recovery candidate adds explicit `--discover-peers --replace-peers` enrollment permission
for workflow, task and document commands. Eligible unfinished parts can discover new peers in
the same exact model cohort when the original pool is unavailable. Each attempt saves an
immutable `executor-admission.json` before any new handle or submission. Original source bytes,
publisher, expiry and completed receipts remain unchanged; uncertain unexpired jobs are not
duplicated. Recovery can use one available peer without weakening the two-peer initial discovery
requirement. Synthetic protocol/coordinator checks are not real-model recovery evidence; the
new-third-peer disposable proof is recorded above. This is not general planning, unlimited pool growth,
a capacity reservation or quality-based model selection. The 123 focused CLI compute tests,
three local-control discovery tests, six agent discovery tests, formatting and strict Clippy
for all targets of those three packages pass. No local model execution was used.
See [automatic executor selection](DECENTRALIZED_AGENTS.md#automatic-executor-selection).

The follow-up recovery slice preserves previously checked terminal failure/cancellation receipts
even after their broker disappears. The owning workflow passes the exact retained handle/status
to reconciliation; a running job or a cancellation request cannot use this shortcut. This avoids
waiting out a lease for a worker already observed stopped, without turning an unreachable worker
into proof of termination. Its focused no-agent-socket regression and strict CLI Clippy pass.
The `agent-jobs-peer-recovery` disposable scenario now covers two discovered initial workers,
one actual worker loss, both original brokers leaving, and a real third-node replacement under
the same owner command. A recorded fixture-only owner pause makes broker cutover deterministic;
it is not product behavior. The checker requires original receipts, new-peer admission before
submission, actual model execution, both protected paths, complete cleanup and unchanged host
state. All 124 CLI compute tests, strict CLI Clippy, the synthetic positive/negative checker
contracts, script syntax and non-mutating scenario previews pass. ShellCheck passes for the
new helper and modified jobs helper; the outer wrappers still report existing baseline/source
context warnings. The scenario and synthetic fixtures alone are not live success evidence;
the corrected original live proof is recorded above.

The [first third-peer recovery run on `5e3ca90d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35597876075)
**failed** during private cleanup, after the owner completed its second attempt on the new
peer. The retained source, original receipts, new-peer admission, real replacement worker and
path captures pass the partial reconstruction; the absent private-cleanup receipt prevents
a complete pass. Both old brokers had intentionally stopped and systemd had unloaded their
transient units; the finalizer incorrectly treated stopping them again as an error. Cleanup
now accepts an already unloaded owned broker only after checking inactive state, no main PID
and no populated descendant cgroup. Loaded-unit stop failures are still errors unless a fresh
query proves collection. Three inert cleanup regressions cover these cases and collection
races; they do not replace the corrected live run. Original network cleanup and host-state
evidence remain preserved, without upgrading the failed run to success.

Local model-update recovery candidate: the enrolled public training loop can now quarantine
an exact imported adapter after a correlated fixed-worker format/value failure and successful
worker cleanup. Only candidate-stage adapter violations qualify; baseline faults, network
failure, resource pressure, cancellation and ordinary quality regressions do not. Original
signed import, baseline, hashes and deadlines remain checked on restart. The accepted warmstart
is unchanged and later revisions remain eligible. This is local adoption/execution exclusion
inside that loop, not a publisher ban, cache-wide revocation or the complete B07 immune system.
All 131 CLI compute tests and strict all-target CLI Clippy pass without local model execution.
The new `agent-artifact-quarantine` scenario fetches a separately signed NaN adapter on R3 and
requires the same loop to continue with real base-model training and successor validation.
Four successful model stages are observed; rejection before candidate inference is not counted
as a fifth. Its pure positive/negative checker, shell syntax, new-helper ShellCheck and topology
preview contracts pass; the modified existing training helper retains two baseline SC2015
warnings. The [run on `bae0d736`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35605406140)
**failed overall**, during the later ordinary artifact import: `CONTENT_PROVIDER_REGISTRY_BUSY`
was followed by selector I/O failure. Its retained evidence does prove the earlier signed NaN
candidate's local quarantine and continued useful training in the same loop; that passing substep
does not upgrade the full scenario. Production correction `f5258b7ad01590afec6e8e74720f246f9f8d8319`
adds a bounded two-second metadata wait. The [new full run](https://github.com/VOLPAROSSA/volparossa/actions/runs/35608519968)
and reconstruction of its 206 original files **pass**, including the independent parent-update
import and inference that previously failed. The same loop rejects the nonfinite candidate,
continues four real model stages/eight updates and publishes its own successor. Fifteen captures
retain 110,977 frames with zero drops or direct client-to-exit packets; all sixteen recorded
peer processes end, private/network cleanup completes and host hashes match. PR #136 is merged
normally into `main` at `08d510d1`. The earlier
[run on `8a21d43d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35600678484) and
[run on `3240e278`](https://github.com/VOLPAROSSA/volparossa/actions/runs/35602912581)
remain failed at their fixture-layout guards, before invalid-candidate construction. Neither
proved quarantine, despite successful cleanup and unchanged-host evidence. B07 remains open.

The new active-adapter recovery candidate addresses a different boundary: a previously approved
peer adapter's extracted local bytes change while its original signed publication and successful
comparison remain intact. The loop restores only its exact, still-valid approved predecessor,
retains a durable local retirement record and keeps the immediate peer predecessor within the
existing eight-round retention bound. Training and serving reconcile to that predecessor without
extending source expiry or execution budgets. If none can be verified, a typed fail-closed path
withdraws the owner selection and stops new broker admissions, including from independent cached
copies. Existing jobs/receipts are not rewritten. Generic worker failures, network errors, busy
devices and quality differences do not trigger this retirement or prove publisher malice.
Interrupted local validation bound to the damaged peer is retained as a failed attempt rather
than retried against retired bytes or reinterpreted against the restored model. Explicit
withdrawal also blocks the initial-base admission window before the next scheduled broker copy.
The affected training-loop, snapshot and broker paths have 60 passing targeted Rust tests,
including the two interrupted-validation checks and initial-base withdrawal check; scoped strict
CLI Clippy passes. The new `agent-active-recovery` disposable scenario exercises real 135M
training P, a distinct node's warm-started Q, independent Q-versus-P approval, corruption of only
the local Q extraction, automatic restoration of original P, protected inference, restart and
continued P-based training. Its signed source catalog admits the next training source only after
recovery; the original enrollment, approvals, expiry and completed job receipts remain intact.
The original fixture failed before training as recorded above. Its replacement cold-fetches
the learner's signed catalog, training/validation sources and Q through its own protected
route, while the producing peer's seed/cache is explicitly owner-provisioned. Selection remains
within the enrolled signed catalog/channels, not unrestricted autonomous source selection.
A passing KVM run is still required: active recovery and full B07 are not live-proven.

Public-document synthesis: `compute peer document --synthesize` chains
real peer inference over the checked fragment answers until one answer remains. A separate
inference-only v3 profile labels generated intermediate text and coordinator-verified lineage;
it never presents that text as an original document excerpt or portable execution attestation.
The same pinned tokenizer budgets every reduction prompt. Original source authority/expiry,
all intermediate packages and full worker receipts are retained across resume. No parent is
discarded to force convergence; non-shrinking reductions, wire truncation, cancellation and
unfinished work remain incomplete. The [run on `342b8a80`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34911606997)
failed before any synthesis worker was observed. Its summary reports ten fragment answers,
but the exported worker evidence proves only the first two workers/four answers; the later
retained-file export was not reached. The concrete cause is a missing v3 branch in the final
`Options::validate` admission gate, before the broker starts a worker. That gate now applies
the same strict, inference-only derived-data validator as the RPC boundary. Targeted admission
and compute tests pass. Incomplete workflows retain fixed diagnostic categories without
upstream text, and the fixture now exports bounded public partial evidence after its owner
returns, before cleanup; this never satisfies the success gates. The corrected
[run on `998b79ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34914382572)
and full reconstruction of its unchanged original evidence **pass**: 5,120 public-source bytes
produce ten fragment answers, then four real synthesis levels (`10 -> 5 -> 3 -> 2 -> 1`),
with eight observed v3 workers and nine independently verified publication signatures.
The final answer has 50 generated tokens and 256 UTF-8 bytes, without wire truncation.
Completed resume after the brokers stop creates no new jobs and leaves retained receipts intact.
Six captures / 28 interfaces / 73,953 frames show no forbidden or direct-exit traffic or drops;
cleanup leaves zero owned objects and unchanged guest-host state. Canonical raw-evidence SHA-256:
`d4968cbbf0f4d13e363dfc87a5c3d2d69069001a5a3883659a7ead6f8dd701ca`.
This proves the inference chain, not answer quality. The original `342b8a80` run stays failed.
General task planning, private offload and B03 remain incomplete.
See [public answer synthesis](DECENTRALIZED_AGENTS.md#synthesizing-one-public-answer).

Current publication-retry correction: a finite training loop no longer stops immediately
after the first handoff once its cycle budget is exhausted. It drains already approved
publications within one shared final `max_seconds` window, without new training, retaining
original identities, source expiry and owner cancellation. Expiry, timeout and pending work
remain explicit. All 34 focused training-loop tests pass. The peer-learning fixture still
requires the actual contribution receipt. The [new run on `6a782752`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34908647293)
reached the bounded 600-second deadline after 600 explicit `agent_policy` rejections, leaving
one publication pending. The learner's Client fixture has no enabled relay/contribution service;
the production publication guard therefore rejects it before accepting the body. The original
catalog cycles, protected peer import, comparison, adoption, eight further updates and validation
have retained raw evidence, but republication and the later independent named-import gate still
do not pass. Cleanup removed all owned objects and preserved guest-host state. Neither this run
nor the failed `08457e1e` run below is relabelled as successful.

The fixture correction places the learner on R3, whose real `provider-c` contribution
service is enabled. Its own agent, cache and five model workers use R3's namespace; three
temporary neighbor links permit selection of two protected relay paths to R4. R3's existing
Exit-facing link permits only its separate TCP18080 serving role, never consumer traffic.
After learning, its service and agent stop and the temporary links are removed before the
original independent Client named-import gate. The [run on `68314466`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34912575899)
completed the five real peer-learning workers, approved one cycle and published it with
`pending_publications: 0`. The full run remains **failed** at the physical capture gate, before
the independent Client named import. All 962 rejected headers were fixed UDP41000-to-41000
attempts to known fixture peers on a dummy `underlay`, not TCP18080 content transfers. The
corrected classifier records only those exact phase/interface/source/destination/port tuples
as `underlay_control_attempt_packets`; this proves neither delivery nor authentication and
does not count as WireGuard or content bytes. Direct-exit, direct content and unknown-tuple
rejection remain unchanged. The corrected combined
[run on `998b79ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34914384494)
and full original raw reconstruction **pass**, including catalog growth to an uncached source,
both real training rounds and their second-source comparisons, protected R3 import/adoption,
eight further updates, validation and actual successor publication with no pending handoff.
The separate original Client named-import gate now also passes with actual received-parameter
inference. The loop's ten captures / 79 interfaces and the learner's five captures / 41 interfaces
contain no forbidden or direct-exit traffic or drops. Cleanup leaves zero owned objects and
unchanged guest-host state. Canonical loop-evidence SHA-256:
`d03fb608d6f6d32f38af189195cad6163ccacf958d9223f5779acfae963112c2`.
No product publication or privacy guard was relaxed, and the original `68314466` run stays failed.
This establishes scoped cross-node continued learning and sharing, not general quality,
defended aggregation or full B05.

Current public-task continuation candidate: `compute peer workflow`, `task` and `document`
accept `--follow` to automatically continue enrolled work across bounded rounds. Completed
receipts and original leases remain unchanged; eligible failed rows prefer another available
compatible enrolled peer. Owner cancellation, original source expiry and retained-attempt limits
stop continuation. All 27 focused peer tests pass, including incomplete-cancellation exit status
and default manual behavior. The [run on `8f49986e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34907950110)
and reconstruction of its unchanged original raw evidence pass: one owner command survived
worker loss, retained the other worker's completed result, and automatically moved only failed
row 0 to a new worker. The replacement appeared 18.821 seconds after loss. Six captures across
28 interfaces show no direct client-to-exit or forbidden traffic; all owned objects were removed
and the guest-host state stayed unchanged. No general planning, private offload, answer synthesis
or completed B03 is established by that run.
See [automatic continuation](DECENTRALIZED_AGENTS.md#automatic-continuation-of-enrolled-work).

Current cooperative-learning slice: `compute train-loop --peer-updates` follows explicitly
enrolled signed adapter channels, resolves their exact datasets only against independently
selected sources, and locally compares an imported update against the actual current adapter
with two real inference calls on the pinned validation source. Only a measured improvement is
adopted. The next local training cycle uses those exact imported files, retains separate foreign
and local lineage, and still needs the normal local promotion gates before publication. The
96 preceding focused compute tests, nine peer-related tests (including original import and
lineage checks), and strict CLI Clippy pass. The [combined run on `08457e1e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34906223498)
reached actual peer import, two comparison inferences, adoption, an eight-update local training
cycle and two further validation inferences. It **failed** the final peer-learning check: the
new local publication remained `publish_pending` after the one-cycle invocation ended. The
original catalog's later independent Client import was not reached, so its earlier failure is
not claimed fixed by that run. Cleanup completed with unchanged guest-host state. The later
`998b79ed` run above supplies the completed cross-node learning and republication proof.
See [peer update enrollment and scope](DECENTRALIZED_AGENTS.md#learning-from-peer-updates).

The preceding version-2 `compute train-loop` enrollment now follows
explicitly selected, signed public source catalogs. The runtime refreshes catalog metadata,
retains stable source/revision progress, fetches newly selected exact datasets independently of
cache availability, and binds the original catalog authorization and expiry to real cycle
admission. The [live run on `50d53733`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34903399004)
completed both real eight-update cycles, four validation inferences, catalog expansion to the
new uncached dataset and a zero-attempt restart. It then **failed** during independent Client
import with `CONTENT_UNAVAILABLE`; the full scenario is not proven. Both original catalogs,
the new dataset, validation source and both published updates independently pass signature
verification. Cleanup completed with unchanged guest-host state. The new combined proof retains
this original gate and adds fixed, non-sensitive provider failure categories to distinguish the
next failure; cache/registry contention is a hypothesis, not an established cause. See
[catalog usage and bounds](DECENTRALIZED_AGENTS.md#signed-public-source-catalogs).

The prior [second-source run on `57fa30f7`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34899111394)
completed two eight-update training cycles, four isolated zero-update inference jobs, both
promotion gates and protected peer adoption. Its workflow remains **failed**: the evidence
checker expected strings instead of the actual worker output objects, then expected a null
`training` field that Rust omits. With those two narrow corrections, complete reconstruction of
the unchanged original raw artifact passes. Checker SHA-256:
`11ba86557ba67563f3b8387a78f3e2084ad8aeddc13fd2c91b527e71466d267c`;
429,704-byte canonical reconstruction SHA-256:
`36484d5caa8b67847769e2adead4059d9f5b771a7fe30f025be43a07b820e7fb`.
The separately selected signed validation dataset is 641 bytes, obtained cold from R5; actual
12-target-token losses are `0.839399 -> 0.656192 -> 0.588994`. Both cycles are approved; the four
generated answers remain identical, so neither better answers nor a live rejection is proven.
The final Client retrieves 943,733 adapter bytes and 1,005 dataset bytes through R4 after R5
serving stops, then uses the exact received parameters. Ten captures / 78 interfaces / 28,567
frames have no drops, malformed or forbidden/direct-exit traffic. Cleanup leaves zero owned
objects; before/after guest-host hash is
`bde4be393adbc2a3e0d380bd06ec8f897003648cee8dd3f7de191e188cea9250`.
The corrected [run on `842e845b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34901453523)
now passes its workflow and exact-source raw reconstruction. It retains both real eight-update
cycles, all four second-source inference jobs and protected adoption; all three original
Ed25519 manifests independently verify. The measured 12-token losses are
`0.839408 -> 0.656203 -> 0.589002`; both candidates are promoted, without a better-answer or
live-rejection claim. Its 430,839-byte canonical reconstruction has SHA-256
`c537beefec5f11a3183235f50c1aa90533d14ad048a78a8fcbb0c1086add67d4`.
Ten captures / 79 interfaces / 27,656 frames contain no forbidden, direct-exit, malformed or
dropped packets; both relay legs carry data. Cleanup leaves zero owned objects and matching
guest-host hashes. B05 remains incomplete for its remaining cooperative-learning scope.

Public-document execution now has scoped live proof. On the earlier `b0c10425`, the startup diagnostic
shows an active/running broker without its socket after 150 polls (17.612 s elapsed,
17.399 s CPU), not a failed service. Before binding, that build synchronously hashes the full
269,060,552-byte pinned model in unoptimized development code. `35fd9551` therefore optimizes
only the pinned SHA-2 implementation in the development profile; it preserves the full hash
verification and existing timeout. Its [actual rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/34901448083)
observes both broker sockets ready in 0.454/0.464 seconds, but fails later before Python starts:
the owner tokenizer reports `stderr_class=proc_mount`. The document fixture inherited the
network service's masked mount view; the candidate now uses the existing net-only owner-launch
pattern while preserving service protections and the actual worker sandbox. The corrected
[run on `1bd44d11`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34903185520)
passes its workflow and exact-source raw reconstruction: 5,120 original bytes become nine
byte-covering portions in three signed task packages, with five real peer-job receipts and
overlapping workers on two nodes. After both brokers and their worker families stop, a resume
completes from unchanged retained files with zero new rounds. Four original Ed25519 manifests
verify; six captures / 28 interfaces / 45,450 frames contain no forbidden/direct traffic or
drops. Cleanup leaves zero owned objects and unchanged guest-host state. PR #125 is merged;
this is public document execution, not private distributed inference or general reasoning.

New user-requested scope: [distributed content caching, publishing and offline delivery](CONTENT_NETWORK_PROPOSAL.md).
Additional scope requested on 2026-09-14: [cooperative trained agents and fully automatic
whitelist/blacklist governance](DECENTRALIZED_AGENTS.md). Its first local CPU-worker candidate
now includes pinned explicit provisioning, inference/LoRA training, saved-adapter reload and
a Rust-supervised mandatory sandbox. Five narrow Rust supervisor tests and the Python
protocol/provisioning tests pass. The first model-runtime attempt on
[`86d2d0f5`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34858211717)
stopped during wheel-metadata verification after the pinned downloads, before any training.
The selector now distinguishes the wheel's own top-level metadata from nested vendored metadata;
six provisioning tests pass. The next guest attempt on
[`a70194ab`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34859406185)
passed provisioning and observed a genuinely isolated Python worker, but stopped before training:
the pinned tokenizer returns a dictionary by default while the worker expected token IDs.
Both calls now explicitly request flat IDs; type and token-budget errors are distinguished.
The corrected worker and distinct-node adapter harness now pass together on
[`38814d30`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34861750881): eight real CPU
optimizer updates change 230,400 LoRA parameters while the base weights stay unchanged.
That initial proof does not cover owner-priority pause/resume/cancellation. The later CPU-pressure
proof below covers pause/resume; B01 remains unchecked for its remaining owner-triggered cancellation scope.
A new `content agent pack/fetch` candidate binds the exact adapter files to the original signed
public dataset and fetches both through the existing protected content plane. Five CLI and four
codec tests pass; the worker's eleven protocol tests cover the explicit read-only input adapter
and pinned tokenizer return contract. The `agent-artifact` guest scenario now requires separate
producer/consumer service processes and namespaces, real training, durable publication/restart,
protected retrieval and execution of the exact received adapter, followed by cache-only reuse.
That real scenario now passes, including exact-source raw reconstruction, unchanged guest-root
state and full cleanup. B02's stated explicit artifact-transfer/reuse/restart scope is proven.
It shares an explicitly provisioned read-only base/runtime; no base-distribution claim is made.
Cache-only retrieval is explicit and off by default. Autonomous training must select eligible
sources independently of cache availability, fetching missing/fresh data rather than silently
substituting cached popular sources. Generalized source selection, external-corpus ingestion,
bias measurement and general task orchestration remain integrations to build. No
distributed training, private AI execution or autonomous content-policy engine is implemented.
The next public-job candidate adds an explicitly attached same-UID inference broker, signed
protected peer submit/poll/cancel exchanges, original-publication/subset verification and
concurrent disjoint-row dispatch. It saves task handles before admission and validates returned
model/input/result bindings. Its scoped two-executor proof is now reconstructed from the real
raw evidence below. Automatic reassignment and general workflow continuation remain pending;
B03 remains unchecked.
Explicit `compute peer resume` now reconciles retained original handles and permits one bounded
replacement attempt per unfinished part, without silently extending an old lease. Terminal
receipts remain observable briefly after cleanup. Broker/peer tests and narrow strict Clippy
pass. The historical happy-path checker failure is retained below; the subsequent live
worker-loss/recovery checkpoint now passes on `0d756a64`.
The first [two-executor run on `c52781f9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34866691641)
stopped during capability lookup, before model execution: an unused initial MPTCP socket
outlived the Exit's 12-second TLS deadline while brokers were prepared. The candidate now
discards an already closed unused socket before obtaining a fresh one through the same helper
authorization, without replaying application work or weakening transport checks. A real local
descriptor regression and narrow agent Clippy pass. The next
[run on `2ba9631e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34869250045)
completed both real peer jobs, returned separate reports and reassembled the two disjoint rows.
It still **failed** the required live concurrency/isolation observation: the detector read only
the process leader's children, missing workers started from other Tokio threads. Both provider
logs reached real model completion; that does not retrospectively establish missing overlap
observations. The detector now follows children of every bounded thread, with a real local
thread-to-child regression. The Rust resource observer receives the same correction so that
thread-created subprocess RSS is not omitted. Four focused supervisor tests and strict CLI
Clippy pass; the subsequent run is described below. The failed run retained complete
cleanup, zero owned network objects and equal guest-state hash
`59ebc76a8e39e0770dece290791c3f79d3f8f15be9ef7a2dbd641716ffb5a0bb`;
its artifact ZIP SHA-256 is
`8c64cba84e945bb6b96ec060de0d77b99affe9f62d9379e92b7454d838c7c4f2`.
The subsequent [run on `4e22b7ce`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34871353888)
retains all required raw observations: two simultaneously live isolated workers on R4/R5,
distinct private runtime/dataset and held-lock inodes, exact disjoint source rows and complete
model receipts, six captures including control / 28 interface rows / 9,488 frames with zero drops or unexpected
outer packets, and zero residual owned network objects. It **failed** in final reporting because
the checker expected `manifest_id` in offline-publish output, which reports a manifest path instead.
Correction `3f5ee282` derives the ID from the original signed bytes and checks their saved hash,
length and publisher/expiry. Complete in-memory reconstruction of the unchanged raw artifact
passes, without synthesizing missing data; the original workflow and report remain failed.
Checker SHA-256: `656cbe862edbf89c2da2e2dc3aceab41f18888ab6baac8475c32eeb5787bece3`;
artifact ZIP: `219ada734fc57f070c8b03483840cdfabb3ab4842d655297f61a5bc0b7464f3b`;
31,434-byte canonical reconstruction: `cfbf4b496200cf647ee3ee571356bad071aa2738b7d70aeef47afc3d0b799a1c`.
Original guest-state hash before/after:
`e592250adbcacd33204e6c855bbc04a548d7498daaeda2c2bc699dbe4ce231fe`.
This establishes the scoped two-public-job execution, not general B03, comparative speedup,
model quality, private offload or live worker-loss recovery.
The explicit `compute peer workflow` candidate sequences up to 32 independently signed public
packages (two to four rows each), with a bounded number of rounds per invocation. Exact source
copies, immutable handles and locally validated full receipts survive process restarts;
completed parts are reused, while pending work retains its original authorization and gets
only explicitly bounded new attempts. These are local receipt records, not independently
portable execution attestations. Whole-job duration is not the per-worker 600-second lease.
General task decomposition, live workflow/reassignment proof and private execution remain open.
The new `compute peer task` frontend fetches one independently selected signed public dataset,
then applies a fixed summary instruction or an explicitly public requester question to its
original contexts through that coordinator. The immutable job binding includes the versioned
task separately from the original publisher-signed dataset. Both agent boundaries verify exact
derivation; peers without the advertised capability refuse it. The frontend retains the original
source, chosen peers, handles and validated receipts, returning ordered per-context answers.
Its current scope is two to four existing inference contexts, not arbitrary-document splitting,
neural result synthesis, confidential prompts or the whole B03 criterion. The 48 focused CLI
compute tests pass, alongside signed-source/agent-boundary and wire-codec checks, scoped strict
Clippy and an actual no-network/no-output CLI preview. The disposable `agent-public-task`
scenario now connects protected custody and fresh source retrieval, two actual worker
observations, exact source/question/result bindings and retained-result resume after stopping
both brokers and the route. The [first live run on `3487f202`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34885058532)
fetched the original source but failed during the second provider's exact address lookup,
before retaining any job handle or submitting work. It remains a failed run, with complete
disposable cleanup and unchanged guest-host state. The candidate now allows at most four
read-only capability probes within 45 seconds, with immediate owner cancellation; no Submit
is replayed. The fixture separately observes actual retained handles before its unchanged
worker-overlap window. Eighteen targeted peer tests and the parser/snapshot checks pass;
the corrective live result is recorded below. Completed full receipts can also be read after the original
source expires; this never renews the source or authorizes unfinished work. These local tests
are not a model-execution claim.
The subsequent [run on `5f487a18`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34888010963)
did execute both real peer workers and returned two source-bound answers. It failed afterward
because the fixture treated two required empty lockfiles as nonempty data files; retained-result
resume was not reached. `42761c28` checks those exact lockfiles separately without permitting
arbitrary empty data files. Its [corrective run 34889536964](https://github.com/VOLPAROSSA/volparossa/actions/runs/34889536964)
on exact `42761c28c6a28c3f60baec7416524ca3f6896ebe` now passes the original report checker and
complete original-raw reconstruction. It retrieves 721 source bytes over protected paths,
executes two actual isolated workers, stops both brokers and the route, then resumes with
zero new rounds. All 15 retained file hashes/inodes and ordered answers are unchanged.
Cleanup leaves zero owned objects; guest-state before/after SHA-256 is
`d6b7d769be7fffacd0b16832dc07d6cd44389423081a3cd452136eb520c86c87`.
Local evidence is `.git/ci-evidence/34889536964/artifact/` with `review.json` alongside it;
the canonical raw rebuild hashes to `3e34d7f5401548b8bc14c1110317ec6d0b646097f0958f363b15f49b074bd467`.
The separate historical Quality job failed `unreadable_literal`; its source fix is included
in `974c6555`, not a retroactive CI success. B03 remains unchecked.

The new `compute peer document` candidate adds actual isolated-tokenizer planning for explicitly
public UTF-8 owner input. Contiguous byte ranges cover the original without truncation; up to
four excerpts form a native signed inference-only v2 package, and multiple package workflows
retain full receipts and ordered range answers. Same-publisher source/fragment authentication,
coordinator comparison against the actual original text and a new explicit peer capability
replace invented training/held-out metadata. A final single-fragment package uses one worker.
The local tokenizer plan does not load model weights; remote inference remains real and bounded.
All 63 focused CLI compute tests, seven dataset tests, three wire-codec tests and three
agent-boundary tests pass, together with strict Clippy for the four changed crates and 21
Python worker protocol tests, with no host model execution. The [first document VM
34891322172](https://github.com/VOLPAROSSA/volparossa/actions/runs/34891322172) on
`974c655520c8690b9e37d23f76361b729a2c9119` failed before tokenizer/model execution:
the Client UID could not read its helper under `/home/vpci/source`, causing
`DOCUMENT_PUBLIC_INPUT_FAILED`. Cleanup completed with zero owned objects and unchanged
guest-state hashes. Correction `4421b1a6de2b0f69bf08873e1c5c9e7a3d419e52` installs only the
public guest helper and an owner-readable, read-only README copy; it does not widen source-tree
permissions. Parser, file and shell checks pass. The corrected exact-source
[VM run 34893180542](https://github.com/VOLPAROSSA/volparossa/actions/runs/34893180542)
passes public-input preparation but fails at worker startup with `compute_result_missing`,
before any validated worker phase. Cleanup again leaves zero owned objects and identical
guest-state hashes. That head's workspace Quality and CodeQL checks pass, but the document
datapath remains unproven. A separate diagnostic candidate retains only a fixed startup
category, exit code/signal and byte count when stdout ends without a result; it does not
log raw stderr or document text and does not claim to fix the underlying startup failure.
The [diagnostic VM on `d29455d3`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34896132212)
stops earlier at `JOBS_BROKER_UNAVAILABLE` for R4, before attach/tokenizer execution. Broker
logs are empty and the original artifact lacks unit exit-state details, so it does not identify
or disprove the earlier worker-startup cause. Cleanup is complete with unchanged guest state.
This is not confidential offload, source-cache discovery, automatic network replication,
neural answer synthesis or completed B03. See [usage](DECENTRALIZED_AGENTS.md#public-document-tasks).
Eight focused peer/workflow tests and strict CLI Clippy pass, including early cancellation
before new submission and reusing full validated local receipt fixtures after restart.
Synthetic receipt fixtures prove coordinator/storage behavior, not remote model execution.
The separate [agent-jobs-loss run on `0d756a64`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34873353570)
now passes, including exact-source reconstruction equal to both original component and final
reports. The guest terminates the observed R4 Python worker via pidfd/SIGKILL while R5 stays
alive, preserves R5's completed result and original handles, and explicitly executes only the
failed row once on a genuinely new R5 worker. Six captures / 28 interface rows / 12,454 frames
have zero drops or unexpected outer packets; both selected WireGuard paths carry data
(774/616 datagrams per leg). Cleanup leaves zero owned objects; guest-state hash before/after
is `7c7da50e0b2570c1ec2c4de8f7a37ed6c6db5a2d89158cd81596d65ba78d7962`.
Artifact ZIP SHA-256: `73eaf3bcfe315e2fe67898076829284ea94e8b9925f78791bc452a168e7e0d73`;
77,280-byte canonical reconstruction: `2ea8f1c769db736928bc42d267d0b765e26dcbdc9584e4a45424bc0cd8beb020`.
This proves bounded explicit public-job recovery, not automatic task decomposition, exactly-once
execution, private offload or the whole B03 criterion.
The explicit `compute train-cycle` candidate now connects an independently selected signed
public dataset, cache-preferred/protected retrieval, the actual bounded local training worker
and a public-ready adapter bundle. The same dataset identity survives a cache miss; fixed
type/size/optional exact identity are checked in the agent before peer-body retrieval. Complete
unexpired cached input can be used without provider availability, but this is not global freshness
or autonomous unbiased source selection. The cycle supports an explicitly imported warmstart
adapter, preserves selection/source/result provenance and does not auto-publish or activate
outputs. Source expiry bounds execution as well as final packaging. Five focused named-content
tests, one request-codec test and strict agent Clippy pass. Historically,
[the first run on `0d756a64`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34873357867)
completed producer training but stopped before the receiving-client cycle when the new route
selected a different control relay. The fixture had bound its provider links to the earlier
probe's relay. That failed run retains full cleanup and unchanged guest state; it proves no
warmstart cycle. B01 and B05 remain unchecked. Three focused training-cycle tests and
five existing adapter-CLI tests pass with strict CLI Clippy. Their synthetic saved-report/adapter
fixture proves source binding and packaging, not real training.
The corrected [live cache/warmstart run 34876251732](https://github.com/VOLPAROSSA/volparossa/actions/runs/34876251732)
passes on exact source `d12768e31c0351e15416f05a8b986905367cab66`. The real R0-to-R1 control-owner
change occurs again and succeeds with exact fresh-owner route/capture bindings. After R4's
eight training updates, a distinct Client retrieves 943,733 adapter bytes and 1,005 dataset
bytes over protected paths. Both providers then stop; the Client performs eight further
warmstart updates in 18,697 ms from its cached signed dataset and exact read-only received
adapter. The 230,400-parameter hash changes from `cf147109c7a5b9ba717f4db1977134a7eadec15d6b4aeaecc95d5c283f7b8193`
to `39437bfdfef3eb5558a0f634e0e1bfa0d303405e4e2ed0ae528ad00bca053109`; the base stays unchanged.
The new 943,733-byte local bundle hashes to `a44e5feecbe21ee2b10a77af8108acd2d58348362df19d7b98418440ae7d6796`
and is not automatically published. Six captures / 28 interface rows / 10,515 frames contain
zero drops or forbidden tuples. R0/R2 carry both WireGuard legs (1,072/509 datagrams per leg),
with six completed MPTCP/TLS streams. Cleanup leaves zero owned objects; original guest-root
before/after hash is `a32b8ff350b2ab12a9f4a8174c9614a02aa4b0208147168d1d2b26a9bffc6696`.
Exact-source report checking and complete raw reconstruction pass; local evidence is
`.git/ci-evidence/34876251732/artifact/` and `review.json` alongside it.
Artifact ZIP SHA-256: `197d53d41de09811c4e19af5c8e914fdb6c7725e19ad5f27e3fa713decca9cb3`;
60,145-byte canonical reconstruction: `3f86a7017eebbcddc410398018bccde6eabd37159c53fa3c5e9a80a76285a5da`.
This proves the explicit receiving-client cycle, not autonomous B05 or the whole alpha.
Owner-priority control adds a persistent private owner-control pipe to the actual
worker. `compute run` and `compute train-cycle` opt in with `--spare-capacity`; peer brokers
always use it and refuse new work while sampled capacity is unavailable. CPU/I/O pressure
pauses model work at an execution checkpoint and resumes after five seconds of observed quiet;
insufficient effective host/cgroup memory cancels and reaps the worker. Pauses never extend
the original deadline. Bounded control/ACK and real standard-library process tests pass.
The [actual owner-priority run 34876248467](https://github.com/VOLPAROSSA/volparossa/actions/runs/34876248467)
passes on the same exact `d12768e3` source, including original raw-bundle verification. Eight
guest CPU contenders drive `some avg10` to 21.3. Worker PID 8832/start 24155 acknowledges
pause sequence 2 at step zero/22,086 ms and resume sequence 3 at the same step/30,685 ms.
It consumes zero CPU ticks during a measured 1.607-second pause interval, then resumes work
and completes eight updates in 40,244 ms under the original 600-second deadline. Total
acknowledged pause is 8,599 ms; the adapter changes and the base does not. All contenders and
worker lifetimes end, model/job roots are removed and no owned objects remain. Original
guest-root before/after SHA-256: `be264df0bda5656d3c2f1ba83c9add51953313006f0ccb54c4bd95d8f0cffbd9`.
Local evidence: `.git/ci-evidence/34876248467/artifact/` and `review.json` alongside it;
artifact ZIP SHA-256: `1f57f69bf4f0c730e11b7f95559871dfc0e36b4566fd69d8e9b9b769b2dd2d5a`;
exact owner checker SHA-256: `87c977a7a23eabef281db45afcf8087cc6204d39385f6bb81a6d0df0d5047131`.
This proves actual CPU-pressure pause/resume, not owner-triggered cancellation or I/O-pressure,
interactive-input, battery or thermal behavior. B01 and B05 remain open. Exact-head Quality,
all three CodeQL language analyses and the aggregate check pass; PR #122 integrates this
candidate through merge `8561bfa41f1639b3b7a9f3a130f95000f8bad47b`, whose tree matches `d12768e3`.

The device-priority candidate extends the real ML admission/worker budget with read-only
Linux sysfs system-battery and thermal observations, cached for at most one second. Charge
at or below 20% pauses, at or below 5% cancels, including on AC/while charging. Thermal zones
pause at 80°C and cancel at 90°C, or at lower relevant trip thresholds with a 5°C margin.
A recognized inactive kernel trip placeholder is not a measured temperature or live limit;
ignoring it retains the software thresholds, while malformed/unreadable observations remain unknown.
Present but unknown data pauses; `not_exposed` makes no hardware-absence or physical-safety
claim. `compute capacity` reports the current combined CPU/I/O/memory/device decision without
model/network execution or device-setting changes. Train-loop worker admission, peer workers
and explicit `--spare-capacity` jobs are connected; seed import and publication remain outside
this ML device-budget gate. There is no logind or comprehensive interactive-activity detector.
All 68 focused CLI compute tests and strict CLI Clippy pass; physical-device evidence remains open.
The new `agent-owner-cancel` disposable fixture targets actual training followed by owner-only
pidfd/SIGINT, a five-second CLI/observed-process cleanup bound, `compute_owner_busy`, no completed
checkpoint and unchanged on-disk base/guest state. Its local parser/file/shell checks pass;
The [actual owner-cancel VM on `43dee7ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34893645697)
passes its exact-source report and original raw-bundle verification: owner-only SIGINT, CLI
reaping after 3.242 ms and all four observed processes ended after 59.420 ms, without fallback
signals or a completed checkpoint. The runtime lock is released and the 269,060,552-byte base
model hash remains unchanged. Cleanup leaves zero owned objects; both guest-state hashes are
`c512a02a7bd7c80acbb93c000b9c95682247d164578afc977c271261ec8edd87`.
Review, source hashes and the original-bundle checker are retained under
`.git/ci-evidence/34893645697/`. Physical battery/thermal and comprehensive interactive-activity
evidence remain open; this scoped result does not check off B01, B03 or B05.

The successor-selection candidate adds a mandatory `source-heldout-loss-v1` policy to new
training-loop enrollment and version-2 state. Technical training completion no longer promotes
every candidate: only finite, consistent reloaded held-out loss strictly lower than its
predecessor by more than `1e-6` replaces the warmstart or enters automatic publication.
Immutable `evaluation.json` binds actual dataset, worker reports, base, input adapter and
candidate files; recovery and publication recheck the decision. Rejected outputs remain
bounded/reclaimable and cannot evict the last approved warmstart or pending approved publication.
Old version-1 loops are not silently migrated or treated as evaluated; their output is retained.
The current training source also supplies the held-out examples, so this is not independent
benchmarking, cross-round contamination prevention, general intelligence or completed B05.
All 75 focused CLI compute tests and strict CLI Clippy pass, including startup diagnostics,
promotion/rejection, restart and reclamation. The pure proof checker accepts all four possible
two-cycle promotion outcomes and rejects inconsistent evidence. These are control/receipt
checks, not live model evidence. The [updated VM on `405e67e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34896078997)
now passes both the exact-source checker and original raw reconstruction (299,551 bytes,
SHA-256 `94060e97d3db4ffca3167bc2d9ca140845edbdc866ea3dbc6335c3e389ef6e87`).
Two actual eight-update cycles approve loss reductions `1.244269 → 0.615178 → 0.345725` on
only four target tokens from the same source. Both successors are contributed and the latest
is retrieved over protected paths and used by another Client. Rejection was not taken in this
VM. Cleanup leaves zero owned objects; guest-state hashes both equal
`550a00b214a77e1dc3dee3f69eb95d6b2f57dd0b6506b973c80ba89ad1503520`.

The second-source validation candidate adds optional explicit `--validation-source` enrollment
with an exact signed manifest and a distinct validation-only public dataset. It pins/retrieves
that same source before training and rejects normalized training-question overlap. After actual
training, two sequential bounded inference jobs compare predecessor and candidate on identical
second-source bytes; promotion requires both the existing source-heldout improvement and this
second-source improvement. The `evaluating` checkpoint retains finished training, and valid
completed stages can be reused with their original reports/deadlines. Partial inference without
a durable supervisor receipt is retained as an explicit failure, not relabelled or overwritten.
Twenty-file completed snapshots bind both stages and the combined decision. The live fixture
is being extended. All 84 focused CLI compute tests and strict CLI Clippy pass; the new tests
cover explicit source enrollment, input overlap, completed-training recovery and source-bound
inference receipt reuse without host model execution. This remains pending model/network
evidence, not an independent benchmark,
historical contamination proof, broad intelligence gain or completed B05.

The next `compute train-loop` candidate connects that real cycle executor to a persistent,
owner-enabled coordinator: cache-independent round-robin selection from explicit public
sources, optional peer-imported initial weights, local successor warmstarts, and separately
enabled signed adapter publication. Each worker retains spare-capacity checks and its original
deadline; the watcher can run until cancelled. Exact enrollment/state and completed-file hashes
support resume. Publication retry reuses the exact signed bytes, original expiry and verified
handoff identity. Eight-cycle retention preserves current weights and unpublished updates.
Focused coordinator/source/storage tests pass, but both initial loop VM attempts remain failed:
[`1b186ad5`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34880750517) observed no worker,
and [`a67729e1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34883408279) confirms that
the seed import finishes at 14 seconds but no cycle is admitted within the 90-second first-worker
window. Both retain complete cleanup, zero owned network objects and unchanged guest state.
The report path-type bug is fixed. The second run's guest-root pressure samples are low, but
do not establish what the owner CLI could read inside its mount namespace. The corrected fixture
uses network-namespace-only entry, preserving the owner's cgroup/mount view, and records
capacity diagnostics from that actual CLI view without lowering admission thresholds.
The [subsequent run on `bf87973a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34885489099)
completed both real eight-update cycles on distinct R4 workers (18.704 and 18.540 seconds),
with unchanged base weights, exact predecessor adapter inodes and two signed automatic
contributions. It then failed a fixture guard that expected only two replicas: the actual
store also held the original dataset and seed, making four. The candidate now checks the two
exact contributed update identities and accounts for only those known optional original
replicas, including bytes/chunks; it does not accept an arbitrary minimum object count.
After the explicit dataset handoff that source must also be accounted for. Final retrieval
and inference by another client were not reached in that run. The original failure retains
full cleanup and unchanged guest-host state. Its partial
cycle proof is stored in `.git/ci-evidence/34885489099/partial-cycle-review.json`;
exact-head Quality and all three CodeQL analyses passed.
The corrective [`bcc1df52` run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34887897332)
now passes fully, including exact-source reconstruction of the original report. Two separate
workers perform eight updates each (21.068 and 20.891 seconds), preserving the base and applying
the exact predecessor. A separate Client retrieves the 943,733-byte second adapter and
1,005-byte source dataset through R4 after R5 stops serving, then performs actual inference
with the exact received weights (12.419 seconds, zero updates). Ten captures / 78 interface
rows / 25,565 frames have no drops, forbidden or malformed packets; both protected WireGuard
legs carry transfer data. Cleanup leaves zero owned objects and original guest-host state is
unchanged. Artifact ZIP SHA-256: `a2e4077ef2d18980e86938a51dd87a8105181581500f03890e55dea68ca11303`;
254,186-byte canonical reconstruction: `591a63244357bb731995c0304a695723430b88aca9b8e3c42719a35e21a7c018`.
Exact-source Quality and all CodeQL checks also pass. PR #123 merged normally into
`main` at `b3e2f08c1a1b9984e6ff536eb609798c24aa312c`, with the exact candidate tree.
These two cycles on an explicitly repeated source are not
fresh-corpus discovery, quality improvement, aggregation, private training or completed B05.
See [usage and limitations](DECENTRALIZED_AGENTS.md#continuous-public-training-candidate).
Concrete prohibited/contextual/allowed content examples are now recorded in that design;
the selected legal baseline is Netherlands/EU plus local exit restrictions, while its enforcement
and contextual decision thresholds remain unimplemented. Existing byte-integrity
and destination-policy checks must not be presented as a moral/legal cache classifier.
The proposal records the full idea and a researched HTTPS integration design: authenticated
origin metadata, publisher signatures, and an optional explicitly trusted witnessed-HTTPS
experiment, through an application/browser boundary. C01–C07 now have source-bound
passing checkpoints within their stated bounded scope; C08 remains incomplete;
ordinary HTTPS, peer hashes or a zkTLS label alone do not establish reusable origin authority.
Scoped downlink and mixed-link runs now pass; content/application integration continues.
Current criterion evidence: [C02 on `d2f886c8`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186359414)
proves two-provider reconstruction and four missing-origin ranges;
[C03/C06 on `603cec9d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178099281)
proves zero initial replicas, foreground P retrieval, extra Q uptake without Q's manifest supplied,
then Q retrieval from a reopened replica after the original provider node stops;
[C05 on `b172d11f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192821990)
proves actual A/AAAA peer-cache hits, local reuse after peer shutdown and cache-only miss/fallback;
[C07 on `b172d11f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192823996)
proves intended-recipient inbox retrieval/decryption after sender application exit and route
disconnect. Older narrower checkpoint labels below retain their historical scope. The
[`b22a9153` provider VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34193391288)
also proves actual overlapping provider bulk traffic; a full expanded-alpha verification on one
build and general speedup remain unproved.

## Current candidate: functional integration in progress

Latest additional functional checkpoints (not a complete expanded-alpha pass):

- [Autonomous replica repair on `cb2e6a67`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34864727782):
  source `cb2e6a674211587cd335e8a712e57d489426e1b2`; a reopened partial holder grows from one
  to three verified chunks on the same cache inode, then supplies a fresh Client after its
  supplying peer stops. The Client reconstructs 786,432 bytes with zero origin bytes and
  SHA-256 `1180e5fb930e654474965694e12accf46c7965fecdec1ec7c511a46702e06097`.
  Eleven physical captures / eighty-six interface rows cover 60,724 frames with no drops,
  forbidden or malformed packets; selected two-leg WireGuard paths carry data during repair
  and retrieval. Cleanup is complete and original guest-state hashes match. Exact-source raw
  reconstruction passes; artifact ZIP SHA-256
  `b075d1f07db52b239baa9697fd8337475132927875bdddbc6d1a38c93bca5591`.
  This proves the configured partial-holder repair/re-serving sequence, not automatic initial
  placement, an independently offline original publisher node or permanent availability.
- [Real training and distinct-node adapter reuse on `38814d30`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34861750881):
  source `38814d30221c11ff73ef688f7a430c8b26fec3fe`; R4 completes eight CPU optimizer updates,
  publishes its signed dataset/adapter and restarts with its durable contribution cache after
  original trainer inputs, adapter and publisher key are removed. A distinct Client retrieves
  943,733 adapter bytes plus 1,005 dataset bytes through two carrying MPTCP/WireGuard relay
  paths, with zero origin bytes, and executes the exact received 230,400 adapter parameters
  from read-only input inodes in its own isolated worker. Cache-only reopening works after
  provider serving stops. Six captures / twenty-eight interface rows have no drops or unexpected
  outer packets; cleanup leaves zero owned objects and original guest-state hashes match.
  Report and raw reconstruction pass; local artifact `.git/ci-evidence/34861750881/artifact/`,
  ZIP SHA-256 `7019f524429c10cf17245008a7ba26f27bd3868d3138a48fd979b83d5b88910d`.
  B02 is covered; automatic training/activation, owner-priority pause/resume/cancellation, model quality and
  distribution of the explicitly shared base/runtime are not claimed.
- [Public custody on `f590aa86`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34850149035):
  two independent configured providers accepted and freshly confirmed an original public object
  after both agents restarted with their persistent caches. The publisher source input/cache were
  removed; normal name-based retrieval reconstructed 2,097,275 bytes from 1,048,699 peer bytes
  (five unique chunks; nine ordered references), with zero origin bytes. All eighteen captures /
  eighty-four interface rows drained without drops, cleanup completed and guest-root state was
  unchanged. This is not an independently offline publisher-node or future-availability guarantee.
- [MPTCP growth on `1aab4caf`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34841782480):
  one live 32-MiB download grows from two to three data-carrying subflows while retaining the
  original Client/Exit metasockets; all six WireGuard legs carry data and teardown completes.
- [Native and HTTPS provider retrieval on `1aab4caf`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34841784259):
  each receives fifteen chunks / 3,932,160 bytes from three genuinely overlapping providers,
  with zero origin body bytes. HTTPS authority comes from a fresh TLS-authenticated origin HEAD.
- [MPQUIC growth on `5b1ba7af`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34838838851):
  one HTTP/3 flow grows from two to three carrying relay paths under actual loss, with complete
  32-MiB upload/download hashes and cleanup. Transport progress is not unique application bytes.

Each report was independently reconstructed from exact-source raw evidence, with retained
before/after guest-state equality. These checkpoints do not prove arbitrary HTTPS compatibility,
general speedup, unlimited paths, physical-radio operation or the full agreed extension scope.
C08 remains open. The chronological records below preserve earlier failures and narrower results;
their pending statements describe those source revisions, not a reversal of later evidence.

Additional local policy integration: startup and periodic reload persist an authority-scoped
version/hash floor after current threshold verification. Six focused policy tests pass, including
separate-process 7-to-6 rollback refusal, equal-version hash conflict, idempotent reload, accepted
higher version and rejected invalid signatures/storage. Strict agent Clippy passes. This closes
the previously identified lack of a durable floor for a fixed configured authority; it does not
authorize trust-key rotation, resist replacement of all agent-owned state or implement AI governance.

The first [automatic-repair VM on `ce2267a6`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34854137170)
reached autonomous one-to-three-chunk repair and a fresh 786,432-byte retrieval from the repaired
receiver after the original supplier stopped. Nevertheless it **failed** physical-capture
validation: control-port/ICMP and other-IP frames remain classified as forbidden. Complete
captures with zero drops and unchanged guest-root cleanup do not waive that failure. The
original failed evidence is retained; no network-proven repair pass is claimed from this run.

Major requested functional work still outstanding:

- General task decomposition, measured owner-triggered cancellation, private distributed jobs and fully
  automatic training/policy governance/self-checking (remaining B01 and B03--B07). B02's explicit
  trained-artifact transfer/reuse now passes the distinct-node checkpoint above.
- Automatic holder selection and network-proven replica repair after a holder disappears.
  Explicit remote Deposit/Inspect and retained-copy retrieval now pass the source-bound custody
  VM above. A new receiver-owned repair worker reopens healthy partial public journals, discovers
  providers and may establish a normal protected route while idle. V4 per-chunk credits bind the
  exact original manifest/missing set; no publisher private key, TTL renewal or LRU eviction.
  Six credit-protocol tests and one production-runtime stream/disk/restart/reassembly test pass,
  as does strict content/agent Clippy. The new `content-repair` protected-network proof is pending;
  these local checks do not prove autonomous placement on new holders or maintained replica counts.
- Normal-browser reuse of eligible content with real origin authority; the existing attachment
  and native-site viewers do not implement generic HTTPS resource reuse.
- Discovering and authorizing useful new relay paths during a live route, replenishing reserves
  and replacing fixed backend path ceilings; current live growth uses already reserved paths.
- Wi-Fi-only joining without prearranged addresses or the fixture's auxiliary Ethernet contact;
  general multi-hop mesh and physical-radio operation are not established by the current tests.
- Owner-priority capacity sharing across multiple interfaces and shared bottlenecks; current
  configured-rate budgets and scoped contention passes do not discover all spare capacity.

`b0e7c36` preserves individually verified peer progress when a parallel stream fails; three real
duplex variants in one focused test and strict agent Clippy pass. The browser-network harness
`d82a64f` passes six local checker tests and twelve parent checks.
`49a0253` adds a fixture-only origin reference using the existing `OriginClient`, a cold private
store and an ordinary Client application socket through transparent ingress. Strict example
Clippy passes; the comparison harness now records actual monotone durations and descriptive
ratios, including results where origin retrieval is faster. SIGINT/TERM drops its private
temporary store. There is no new user CLI benchmark flag or measured network speedup result.

The owner-contention harness `910a3ac` extends the existing replication topology with a
524,411-byte, three-chunk Q. It requires actual capless owner UDP traffic on the configured local
link, one permitted in-flight chunk, a quiet provider-payload interval and resume on the same
provider connection, followed by verified Q retrieval and complete cleanup. Twelve capture
tests, five evidence tests, the seed test and narrow shell checks pass locally.

The [owner-contention VM on `b9404908`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34197447110)
proves actual same-flow pause/resume: 2,170 owner UDP packets carry 2,604,000 bytes during
3.0004 seconds; the observed provider application-payload windows contain 263,914 bytes before,
zero during and 263,679 bytes after that load. All three Q chunks are retained and the replica
reopens. The scenario nevertheless **fails** at the later fresh Client retrieval with
`CONTENT_PROVIDER_TLS_FAILED`; there is no final Q output hash or complete C04 pass. Captures
are complete with zero drops/forbidden packets and cleanup leaves guest state unchanged.

`c75ab91` fixes a reproduced parent-ingress error behind that failed return path: kernel TCP
ACK/RST packets emitted before `accept()` lack the socket file required by `meta skuid` and
were redirected into client ingress. A genuine trusted-UID SYNACK now binds only that incoming
connection's reply direction to the helper's exact runtime label; original-direction traffic
and other UIDs gain no exemption, and a new SYN revokes the old marker. There is no generic
established-flow bypass, TLS relaxation or new agent/helper RPC. The actual Rust-encoded nft
batch passes the disposable reproduction: misdirected replies fall from five to zero, the
full TCP request/response completes, wrong UID and original-direction attempts remain blocked,
and two injected stale SYN markers are cleared. Three existing parent tests and strict helper
Clippy also pass. The privileged regression is explicit opt-in. The
[integrated C04 run on `fed8ab33`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34203089267)
now **passes** its exact-source report and raw rebuild. During 3.001237 seconds of owner load,
2,088 UDP packets carry 2,505,600 bytes. The same provider TCP flow has 263,912 payload bytes
before, zero during and 263,679 after that load, observed independently at Provider and Exit.
The replica reopens and delivers all 524,411 Q bytes / three chunks while the original provider
is offline, with SHA-256 `22da54d461a4bfef4e32682d16db4771dd1a810e032aebbc669618259601326a`.
Both selected WireGuard paths carry data; all ten physical captures are complete and zero-drop
with no forbidden traffic. Cleanup leaves zero owned objects and byte-identical guest state.
Artifact ZIP SHA-256: `c386851aa45c9de794b3dc1d3fe0c5d01c18e40e8beb1cd75b00bf295ed28d7d`.
Together with existing bounded quotas/min-free-space/non-eviction and foreground cancellation,
this satisfies C04's local bounded-contribution criterion. It does not establish global fairness,
general disk-I/O QoS, retention repair or a universal no-slowdown guarantee.

The [browser/provider VM on `b9404908`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34197445147)
passes its native two-provider download but **fails before the browser consumer starts**: the
capability-dropped UID cannot traverse the private checkout to load the Python driver.
`af1701da` stages only that public driver and its imported dependency in the existing root-owned
test binary directory; no checkout permissions are loosened. The
[corrected run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34199383486) delivers native,
one-use browser HTTP and partial-origin downloads with the exact 2,097,275-byte hash. Two peers
supply the complete browser object; the missing case obtains 1,048,699 peer bytes and exactly
1,048,576 origin bytes in four ranges. The observed private spool is removed. All eighteen
present captures are complete/zero-drop with unchanged privacy predicates; guest state is
unchanged and cleanup leaves zero owned objects. The scenario still **fails** before its origin
reference because that capture prefix was not registered. `5f648434` adds only the exact prefix
and a guard regression, with no packet-predicate relaxation. The
[new reference run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34201378552) now **passes**
the complete unchanged-source report and raw rebuild, including ordinary publication and named
retrieval. All 34 captures / 164 interface rows are complete with zero drops, truncation or
forbidden packets, and cleanup leaves zero owned objects and byte-identical guest state.
Artifact ZIP SHA-256: `4e0b8af49af9339570eaa3059d531c994657909aebf289a47ceede0b03b46e04`;
raw rebuild SHA-256: `12b33191a38605bea6593ed950b52554ad2a7e5b778047415cd5975dcbcd109f`.

The actual comparison uses the same exact object/hash, two relay paths, Exit and route context:
the complete peer-assisted browser command takes **4.398605732 seconds**, versus
**1.623640130 seconds** for a cold origin-only full retrieval through normal TCP ingress.
The origin is about **2.71 times faster in this one sample**. Browser delivery avoids all origin
body bytes; its final localhost HTTP GET takes only 10.9 ms, which must not be substituted for
the complete command time. This VM executes an HTTP consumer, not a browser engine. Useful
cache/origin latency selection is still unfinished; neither general speedup nor owner-goodput
is guaranteed. C08 remains unchecked; the newer C04 result above supersedes its earlier failure.

Quality on `1283` failed
`refreshed_control_lineage_keeps_forwarded_exit_selectable`; its random fixture nonce can collide
with the fixture's Exit/control network hints. Forcing that collision reproduced the same
sampler rejection; using the existing distinct-discriminator fixture helper passes both the
positive test and existing collision rejection test, plus strict agent Clippy. The
[full Quality run on `b9404908`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34197426766)
now passes formatting, locked dependencies/licenses, strict Clippy, workspace tests,
namespace-backed proof reporting and the non-mutating integration harness. This does not turn
the separate failed network runs into passes. The earlier `b22a9153` provider and `b172d11f` DNS/mailbox
network evidence above retains its exact source scope and is not extended to these candidates.
The newer [full Quality run on `fed8ab33`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34203066709)
also **passes**, alongside the exact-source C04 and site/provider VMs above/below. The later
source-strategy changes have their own verification and do not inherit that result.

### Native static-site application

`dd19ffa` adds `content site pack`: a canonical bounded multi-asset object from explicitly selected
regular files; the existing native identity/publication/provider commands sign and distribute
it. `content site open` uses the sealed named-download result, original authority deadline and
complete canonical bundle to expose verified assets on an ephemeral, exact-host loopback URL.
HTML/CSS/JavaScript, root-relative/directory/UTF-8 paths and single media byte ranges are
implemented; immutable query strings do not create a dynamic backend. Browser isolation does
not confer an external HTTPS origin, cookies, persistent storage or service workers.

Two codec tests and strict content Clippy pass. Four targeted CLI pack/HTTP tests and three real
named-transfer CLI process tests pass, including site assets, ranges, expiry, listener shutdown
and private spool cleanup. A separate explicit installed-Firefox run also passes in 2.36 seconds:
the host filesystem is read-only, network/PID/user namespaces are disposable, the viewer and
browser have no capabilities, and only the owned fixture/evidence storage is writable. The
rendered screenshot visibly contains the expected JavaScript-replaced text in CSS green, SHA-256
`01c64a9fb42b7b40d902020a9c3f7a0aa349012dc017c42aa219ba1de1c66c28`.
This is actual browser execution behind the real local named-transfer protocol. Separately, the
[site/provider VM on `fed8ab33`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34203091361)
now **passes** ordinary `init`/`site pack`/`publish`, provider imports and protected `site open`
after the publisher application exits and its identity, assets, bundle, manifest and source cache
are removed. The independent Client supplies only its trusted publisher key and name; two
providers deliver nine chunks / 2,097,628 bytes with exact bundle SHA-256
`5e3012170ca5335e4f8b7e419fda3ae4ddf59e7603eeabb6a9c2544ea6088a04`.
Four real HTTP assets, HEAD and a 4,096-byte range return the exact bytes/MIME; wrong Host and
traversal are refused. SIGTERM removes the private spool and listener. All forty captures /
192 interface rows pass the unchanged boundary predicates, with zero drops or forbidden packets;
cleanup leaves zero owned objects and byte-identical guest state. Artifact ZIP SHA-256:
`3d7a0bd4605cdcbec76d65134a36888a9d6d042ee59a815ff8557198f2df0181`;
exact-source raw rebuild SHA-256:
`2c414bc7d5e738ea23bd97e5f750b6965c69508c6d6ff248063a23592e1bb86c`.
This VM executes HTTP requests, not Firefox, and proves publisher-application exit rather than
power-off of a whole provider machine. Its HTTPS reference again shows no latency benefit:
7.567 seconds peer-assisted versus 1.848 seconds origin-only (descriptive ratio 0.244212).
Run the opt-in browser proof with `sh tests/integration/site-browser-smoke.sh`, supplying
the built named-download test executable and a new empty `0700` evidence directory; it installs
nothing and does not disable Firefox's sandbox. See [site commands](OPERATIONS.md#native-static-websites).

### Measured source selection under development

HTTPS now exposes `--source-strategy auto|peers-first|origin-only`, defaulting to `auto`.
Automatic selection retains verified local chunks, requires fresh origin authorization and
prefers the origin when there is no recent comparable origin/peer cost. Two RAM-only useful-peer
hints are scoped to the carrying route context, control Relay and policy; they retain no object
catalogue and never replace newly authenticated provider offers. Cost hints expire after at
most sixty seconds and cannot extend signed-offer validity. An admitted peer attempt includes
fresh exact lookup and protected transfer in one bounded budget, retaining verified progress
and ending both workers before origin fallback. No full-object origin race is introduced.
The explicit `peers-first` mode supports deliberate peer-path exploration/tests, not a speed
claim. Seven targeted agent tests pass, including actual chunk transfer followed by a source
deadline, retained verified counts and both worker owners dropped before fallback. Three
CLI/local-control strategy tests, strict agent/CLI/local-control/example Clippy, ten HTTPS and
fourteen parent checker tests also pass. The additive harness compares two cold product
`origin-only`/`auto` downloads, binds their exact origin/peer byte accounting and reports actual
monotone durations without forcing a winner. The
[network run on exact `8830a57a381cc3ce77a1b1303385216f46ac8da1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34205965849)
now **passes**, including an independent rebuild from the raw artifact. Explicit origin-only
takes **2.553865542 seconds** and auto takes **2.684187122 seconds**, with distinct cold stores,
the same 2,097,275-byte object/hash and unchanged protected route context. Both obtain zero peer
body bytes and one full origin range. The actual `ORIGIN_PREFERRED` event precedes auto's body
retrieval; no failed peer payload attempt is hidden. This proves the origin-preferred branch,
not successful automatic peer admission, budget fallback in the VM or a latency gain.
All 52 captures / 248 interface rows are complete and zero-drop, with no forbidden or direct
Client–Exit packets. Cleanup leaves zero owned objects and byte-identical guest state.
Artifact ZIP SHA-256: `950f8f341772884e1814d6af29ef536d2e7e8d68edd89118d58fb4b7bc4e20c6`.
The [Quality run on the same commit](https://github.com/VOLPAROSSA/volparossa/actions/runs/34205947343)
also passes. Neither result completes C08 or verifies later changes.

### Origin-authenticated representation-digest integration

The new explicit `--origin-digest` mode is connected end to end through origin TLS, protected
provider lookup, normal agent retrieval, local control, `fetch-https`, `browser-download` and
automatic public contribution. It replaces the custom metadata-path requirement only when the
origin itself supplies supported SHA-256 `Repr-Digest` metadata on a fresh authenticated HEAD.
The anonymous public binary profile remains bounded; missing/unsupported digest metadata
returns unavailable. It does not make ordinary unsupported HTTPS sites shareable.

An original provider-signed manifest is an untrusted transport index. The complete ordered
object must match the live origin digest before Ready, output or contribution. Original HTTP
and native expiry are both retained. Incomplete peer delivery stops before one full origin GET;
this new mode does not claim partial origin ranges. Native registration retains original signed
indexes without implicitly enabling name lookup or incidental replication. Local/browser JSON
distinguishes `origin-repr-digest` from `cooperative-origin` and exposes `transport_manifest_id`.

Four digest library tests pass, including real origin TLS/HEAD/full GET, rejection of a false
chunk index and actual provider query/transfer. The existing cooperative TLS regression also
passes. Agent check and strict content/agent/CLI/local-control Clippy pass, as do the wire-mode
and parser-mode tests, four isolated CLI-process tests, the legacy parser test and two origin
fixture tests. Eleven HTTPS and fourteen parent-provider checker tests and narrow shell checks
pass. These local results do not establish network delivery or browser-engine behavior.

The [additive provider run on exact `f3abee8e7183381ef1fb00e05bbc2783bf16900b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34212634858)
now **passes**, including full independent raw rebuild using that commit's checker, not the
later dirty worktree. Fresh HEAD+full GET supplies 2,097,275 origin bytes and zero peer bytes
to one cold cache. Fresh HEAD+two providers supplies all 2,097,275 peer bytes / nine chunks and
zero origin body to a different cold cache, preserving the same protected R2/R1 route context.
Whole-object SHA-256 is `add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`;
the peer hit retains original transport manifest
`32ec1dfd49cc4e7739d1b46d7b03e5ba98224e6e868aee0c626c02f583d6a805`.
Origin-only takes **2.576731230 seconds**, explicit peers-first **9.230297498 seconds**.
This avoids origin payload transfer but does not improve latency or prove automatic peer
selection. C08 and arbitrary-site compatibility remain unproved.
All 64 captures / 304 interface rows pass complete zero-drop boundary checks; cleanup leaves
zero owned objects and byte-identical guest host state, SHA-256
`8912e8acbc4416f8cf00d506bc2cac073d07f802fcdaee2dbc6d6aeaffb608fe`.
Artifact ZIP SHA-256: `c4d419b330703d14a514c30138de53f7a390f79b6878f05dc75ecd82452c9ed1`;
canonical raw rebuild SHA-256: `ea64f62341a0e0a300c625bc75fc4a8d21d6a9362e02ce2966ad35b648aea545`.
This result does not verify the later native cache-only site extension.
The [full Quality run on the same `f3abee8e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34212584855)
also passes; it does not certify subsequent worktree changes.

### Independent digest copies and bounded recent-peer lookup

The following implementation fixes a real interoperability gap: independent origin downloads
sign different native transport envelopes for identical bytes, while the former consumer sent
one chosen manifest ID to every provider. A provider holding only its own original index rightly
answered missing. The new public-layout constructor retains each worker's own original index
and expiry, requiring the exact same whole hash, length, media type and ordered chunk list.
Ordinary native/named/private transfers retain their original exact-index constructor. Nothing
is re-signed, provider keys gain no origin authority, and complete origin verification still
precedes output or public contribution.

An actual two-provider v1-stream test passes with independent signers, distinct indexes and
complementary caches: four unique chunk requests reconstruct five ordered references with the
correct complete hash. The original exact selector still rejects the other index. The existing
parallel lifecycle test and all 38 targeted agent content/discovery tests also pass, along with
strict content and agent Clippy. These are local protocol checks, not an independent-index VM pass.

The integrated harness now replaces only provider B's registration after the origin-only case,
retaining its same four-chunk cache and original publication expiry. Its next digest retrieval
must use both independently indexed providers, reconstruct every byte and fetch no origin body.
Three fixture tests, twelve HTTPS checker tests, fourteen parent checker tests and narrow shell
checks pass; the actual new VM result follows below.

The earlier `f3abee8e` logs identify **5.146 seconds** of discovery inside the 9.230-second digest
peer operation. Both offers were already verified before another **5.034 seconds** waiting for
DHT completion; the previous descriptor operation refreshed those same peers in 45/68 ms.
The remaining 4.084 seconds cannot be attributed solely to payload from the available evidence.
Explicit peers-first now tries freshly revalidated route/policy-scoped hints within one second,
then bounded generic discovery/pairs if needed under its original thirty-second deadline.
No full-object origin race is started; actual verified progress survives successive pairs.
Automatic mode retains its existing measured budget without generic discovery fallback.

The [exact `3357169e` provider VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34218261300)
and [full Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34218225907) now **pass**.
The raw rebuild equals the report using the committed checker archive. Provider B keeps its
same cache (`65025:27140`) and four original chunks / 1,048,576 bytes while registering only
its independently signed index. Both original layouts and expiries match. A fresh origin HEAD
plus both providers reconstructs all 2,097,275 bytes / nine chunks with zero origin body/ranges,
SHA-256 `add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
Both selected R2/R1 WireGuard paths carry the protected MPTCP transfer. Earlier native,
browser-download, missing-range, named, site and cache-only phases remain green.

Actual recent lookup replies arrive 42/64 ms after dispatch, without the earlier five-second
DHT wait. Whole digest retrieval takes **4.914942182 seconds** versus **2.544424960 seconds**
origin-only: still no latency win, automatic peer-selection proof or complete C08. All seventy
captures / 332 interface rows are fully accounted and zero-drop/forbidden; 123,514 summed
boundary frames are not unique packets. Cleanup leaves zero owned objects and unchanged guest
state, SHA-256 `cd650c0f9e48bcb705ab61fe7c96f1ffe584283053bc39d09d1a60aba0ba635c`.
Artifact ZIP SHA-256: `5aa3343a1242fd2a88807897b0931f8253caad107d6ef11d8fd4ae1487777b5e`;
canonical raw rebuild SHA-256: `3cd6f47de03e6eb6bea06e8b84cf40bd1a52b5bd7be43d8531c0fecb4237901b`.
The fixture-only route-network discriminator correction also passes in this full Quality run;
the original `4e6cc308` failure remains recorded below. These results do not certify subsequent
explicit-publication changes or resolve separate CodeQL review findings.

### Explicit complete publication through the configured service

`content publish --contribute` now links local signing to the existing configured provider,
including ordinary `site pack` bundles. Offline publication remains the default. The CLI
retains the original signed/verified envelope in memory, saves its local manifest first and
releases signing-key ownership before IPC. It streams bytes from its private user cache over
the existing authorized Unix socket. No key, user-source path, replacement endpoint or caller
quota is handed to the agent. Ready echoes the exact contribution mode; legacy agents and
ordinary handoffs cannot silently substitute one mode for another.

The agent requires its already configured healthy public contribution service, receives into
bounded private staging, and holds the existing foreground/background-writer ownership across
admission. Only complete verified bytes are non-evictingly admitted into the actual configured
cache and durable original-envelope journal before live registration and offer announcement.
Final `network_publication` requires the complete original object, a live service and unchanged
expiry. Empty public objects are supported; private messages are excluded. Failed/partial
admission does not produce a publication acknowledgment or delete the completed user copy.
Staging closes and is removed on completion/cancellation. This is local publication and restart
restoration, not external custody, replica repair or guaranteed offline website availability.

Four targeted core admission tests pass, including complete/idempotent/repeated-chunk/empty
restore, quota-prefix refusal, non-eviction and private/expired rejection. A wire test confirms
the additive mode/receipt fields and forbids caller-selected service storage. Three real CLI
process tests, the explicit parser test, the existing offline publication test and strict
content/CLI Clippy pass. CLI tests use a simulated authorized agent endpoint, not a network
substitute. Three new agent tests and three existing import/export tests also pass, including
actual original-object transfer after journal restoration over the v1 duplex stream, a real
Unix mode exchange, empty-object support and staging/lease cleanup. Strict agent Clippy passes
for the normal production library and all targets/features. The existing pinned `tempfile`
workspace dependency is promoted from agent test-only use to production staging; no package
or lockfile version changes. The final targeted provider group (eleven tests), local-control
content group (thirteen tests), workspace formatting and diff checks also pass. The additive
network fixture retains the earlier P/Q and automatic-contribution phases, then uses the normal
CLI to publish a site, removes its private source, restarts the actual configured provider and
fetches by publisher/name from an independent client with fresh path captures. Nine checker
tests and narrow shell checks pass, including the earlier two-file owner-probe staging. Its
real publish/restart/network execution is now verified below.

The [exact `ac782769` publication VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34221501655)
and [full Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34221442109) **pass**.
The complete raw rebuild equals the report using all six transitively required Python sources
from that exact commit. The normal CLI acknowledges 2,097,628 site bytes / nine chunks. The
same configured R4 cache (`65025:27281`) retains its earlier P and now contains two publications,
twelve chunks / 2,622,237 bytes. After removing the publisher's identity, source, manifest and
cache, the actual provider PID changes 23288 to 23395 in the same namespace. Its original
1,621-byte journal remains byte-identical, SHA-256
`71aae7d80815ad33433320dda75fb6c6cc472deca421178c69cba28a8643f43d`.

An independent capability-dropped Client supplies only the publisher key and name and receives
the complete site from R4, with manifest
`e748a051bc61a913033045b9482227f47f5fd5fc89f9b990babadc5887bf4434`, original expiry 1788954885
and bundle SHA-256 `5e3012170ca5335e4f8b7e419fda3ae4ddf59e7603eeabb6a9c2544ea6088a04`.
Its fresh context `49623c6bb9c5859bc1f172a5b7d65d21` uses both R1/R2 WireGuard paths. Earlier
Q redistribution and automatic P uptake/restart/retrieval still pass. All twenty-five captures
/ 196 interface rows are complete, drained, accounted and zero-drop/forbidden/direct; the
37,759 summed boundary frames are not unique packets. Cleanup leaves zero owned objects and
unchanged guest-state SHA-256 `3e79745caded681ddac6cd2fdd3d1f11481f7ae0c0f929d86d734cb51fdf0679`.
Artifact ZIP SHA-256: `22aa51325ed41ee6953f083eea0cb7be3662a7cfd025005564a87f7f79026ae6`;
canonical raw rebuild SHA-256: `041b71ef4ab8a5442411cc83f21edb7dca046e0407ef804e6a4ef78bf7d92323`.
This proves publisher-application exit, not power-off of the provider node, a browser engine,
external custody or the later cost-aware source-selection changes.

### Cost-aware automatic digest retrieval

At most two digest-index lookups now execute together under the same original absolute
deadline. Results remain in input-provider order, preserving each original index and the
sixteen-provider bound; timeout/drop does not leave detached lookup owners. A real duplex
selector barrier proves both requests arrived before either response, with sibling retention
and deadline cleanup. The previous compatibility/private-index test also passes.

Digest Auto now requires a successful recent index-cost measurement alongside the existing
protected payload measurement. Only complete origin-verified delivery can attach this fixed
cost to an already useful exact-scope/provider hint. Its sixty-second age starts at the index
operation, not later attachment; no offer, payload age or content authority is renewed.
Initial admission adds the slower parallel index cost to the conservative payload estimate.
After fresh indexes actually arrive, it checks the selected peers' remaining payload estimate
against the same original deadline, without counting index time twice. The measured-peer
event follows that check; ordinary native/cooperative prediction remains unchanged.

Three final targeted tests and strict agent all-targets/all-features Clippy pass, alongside
formatting. The additive comparison uses one predefined 4-Mbps disposable origin uplink for
origin-only calibration/reference, peers-first calibration and a cold automatic download,
without replacing earlier fast-origin or missing-chunk tests. The first network execution and
its checker failure are recorded below; C08 stays open.

Thirteen HTTPS and fourteen parent checker tests pass. Shell syntax and targeted ShellCheck
also pass. One local disposable user/network namespace checks the actual iproute2 schema and
exact cleanup (`noqueue -> TBF 804: -> noqueue`); it carries no test payload and proves no
throughput. The new fixture requires fresh HEAD authorization, both independent providers,
zero origin body, unchanged original indexes/expiry and one common window under sixty seconds.
Its separate `benefit_passed` field is calculated only from the complete command durations;
a slower automatic sample remains false. The limiter is removed before the earlier fast-origin
tests and through the existing failure cleanup. The origin's original 31-connection cap stays
unchanged; four additional raw records are explicitly accounted.

The [exact `2769761c` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34223916952)
**fails** in HTTPS evidence finalization: the object-only JSON reader receives the actual
`tc -j` qdisc array. A subsequent in-memory diagnosis also finds an empty, unselected R0 capture
being required to contain traffic. Both issues are checker-only: the correction accepts bounded
qdisc arrays only at that seam and allows silence only for the independently verified unselected
relay. Selected relays, Client/Exit, complete capture intake/accounting and every privacy
predicate remain mandatory. Fifteen HTTPS checker tests and fourteen parent tests pass.

The original workflow/report remain failed; ordinary publication, named and site phases after
the finalizer did not run. Its [full Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34223896953)
passes. Re-evaluating the retained HTTPS raw evidence with these two corrections and exact
unchanged checker dependencies passes, with SHA-256
`183ab4f5ebebc35bdfa85f4a5a707236d8690a8bcc504802cbe8de40c2570044`.
The actual automatic source event and receipt show both independent providers, all 2,097,275
peer bytes and zero origin body after fresh HEAD authorization. Complete command durations are
**6.307903196 seconds** origin-only, **4.164107493 seconds** peers-first and **4.092074725 seconds**
automatic, within one 17.223931781-second window. Thus this single constrained-uplink sample is
about 1.54 times faster via automatic peers; it is not a general speed or owner-fairness claim.

The fixed qdisc options remain unchanged throughout and cleanup restores `noqueue`. All 65
captures / 306 interface rows are complete with exact socket accounting and zero drops or
forbidden/direct traffic; 119,564 summed boundary frames are not unique packets. Cleanup leaves
zero owned objects and equal guest-state SHA-256
`eb70cea1c179e32b54fa29d85c9fd0366a3f25377573255fdb30d50af0847b3d`.
Artifact ZIP SHA-256: `9328af15ced2ea4a84f82d5232cb6a4b162229cd1407ceb68b977d178701d2bc`.
No full corrected-source VM pass or expanded-alpha completion is claimed.

The subsequent [exact `6d3f44d` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34227589468)
**passes** with the committed corrected checkers and adaptive worker runtime. Its complete raw
rebuild equals the top-level transfer report; independent HTTPS and ordinary-publication rebuilds
also match. Earlier native/two-provider, browser consumer, four missing-origin ranges,
independent-index digest, ordinary publication, named retrieval, site and cache-only phases all
pass. This is not the later three-provider scenario or a browser-engine/full-alpha claim.

Actual fixed-uplink command times are **6.392691790 seconds** origin-only, **4.118268956 seconds**
peers-first and **4.319381088 seconds** automatic. Auto chooses both providers and receives all
2,097,275 peer bytes with zero origin body; this single whole-command sample is about 1.48 times
faster. The unchanged qdisc and original authority remain within one 17.311804233-second window;
the limiter is removed afterward. All 88 captures / 416 interface rows have exact stopped intake
and socket accounting, zero drops/unexpected/direct traffic. The 152,074 summed boundary frames
are not unique packets. Cleanup leaves zero owned objects and byte-identical guest state,
SHA-256 `2cd5a285bd5b878fd412a93513957ff97e782648988148c9cbe89d2a94b067b0`.
Artifact ZIP SHA-256: `7460fb85e4740a4d59ae4c804e430fc839f3cca2c4cc77a7ee75ffc708793099`;
canonical raw rebuild SHA-256: `9ae980b60e816a7a2ed0f67ce730df6dba51202630a6ad152eef601e1da18a30`.

### Adaptive cache-worker integration

Native/named downloads now pass their bounded candidate batch to a dynamically sized coordinator,
with one writer and per-provider attempt sets rather than a two-element array/eight-bit mask.
At most two start; dormant candidates own no stream. Every later assignment first acquires a
shared RAM/descriptor resource lease, then opens the unchanged protected route/TLS/provider
protocol. All futures stay joined under the original deadline, with no detached tasks or duplicate
in-flight chunk requests. Each provider retains its exact original transport index and authority.

The controller can add a probe for useful missing content or observed aggregate throughput.
Further rate-based growth requires at least ten percent gain in verified bytes per monotone
wall time across a complete contributing batch, not a sum of overlapping per-peer rates.
Unhelpful probes finish and stop further throughput growth. Pressure drains surplus streams
after current responses, preserving at most one per existing download and blocking new shared
admission while any worker remains. It does not promise globally evicting every stream but one.
RAM/descriptor resource leases are global to the content runtime, derived
from read-only RAM/cgroup/descriptor headroom; unavailable pressure data does not imply idle
capacity. This is advisory accounting, not a kernel reservation or universal owner-speed promise.

The final targeted core filter passes three tests, including six actual v1-stream adaptive
variants: complementary three-provider delivery, failed stream, one/zero resource slots, a
tenth provider, and active three-to-one pressure draining with continued bytes/full reconstruction.
Strict content Clippy passes. Four targeted agent tests pass, including the actual assignment/
lease driver opening three of four candidates, twelve verified chunks/full hash, all leases
released, and a last-moment resource refusal opening no stream. Three resource-accounting tests
and strict agent all-targets/all-features Clippy pass. These use backpressured duplex streams
and deterministic resource samples, not physical network or operating-system pressure measurements.

The actual three-provider protected-network proof now passes on `d0251a27`, recorded below.
Subsequent HTTPS batching, control admission and mesh-neighbor integration are described below;
sixteen remains the bounded discovery-message input, not an adaptive active target. Native
MPTCP/MPQUIC backend ceilings have not been generalized. These are bounded integrations,
not the entire user requirement.

The additive protected-network scenario is now executable in the existing disposable provider
topology. After the unchanged earlier phases and route retirement, a fresh route retrieves
fifteen unique chunks / 3,932,160 bytes from disjoint R3/R4/R5 caches (five chunks each), with
SHA-256 `26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011`.
The independent publisher exits and its complete temporary source is removed before fetch.
The original public manifest is copied to the Client; its mount cannot read provider stores or seed state.
The checker requires all three providers' actual kernel-timestamped bulk-payload windows to
overlap, both selected WireGuard paths, exact reconstruction, six drained captures and normal
service/route cleanup. Three IDs in a receipt alone cannot satisfy this proof.

The fixture restricts only Client control-UDP41000 on its three spare-node interfaces before
Discovery starts; the real independent control peer must then be R0/R1/R2. Three new, separately
named broker links carry only exact UDP41000 control traffic. Their actual routes and the
Client filter are retained; no production selection rule or host network is changed. One narrow
seed/reopen test and strict example Clippy pass, as do four new evidence tests, fifteen parent
tests, ten observer tests and targeted shell checks. A disposable user/network namespace accepts
and removes the exact nft filter, ending with an empty ruleset; this carries no payload.
The actual three-provider result is recorded below; earlier source-scoped reports do not gain
this new required proof retroactively.

The [first `8247ebcd` attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34229670864)
**fails before reaching that phase**; its [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34229455721)
passes. Limited Auto legitimately selected the origin (`ORIGIN_PREFERRED`), adding one full
GET to the five fresh digest HEADs. The HTTPS checker assumed Auto always selected peers and
assigned that extra body to the following missing-range metadata phase. The correction accounts
for either actual complete-source choice, requires its matching fresh event, exact TLS/body/
provider accounting, and preserves every subsequent original range and metadata check.
Sixteen HTTPS and fifteen parent checks pass, including rejecting omitted/duplicate records and
falsely relabelled peer benefit. Rebuilding the complete retained HTTPS component with this
correction passes (canonical SHA-256
`4b52b5420db650e956b8ebf359d6011191319bc104037cac2b099d94530cfbb5`);
the original workflow remains failed, not a completed parent or three-provider proof.

That fixed 4-Mbps sample measures 6.629 seconds OriginOnly, 4.548 seconds PeersFirst and 6.625
seconds Auto. Auto obtains all 2,097,275 bytes from the origin and no peer object bytes: the
3.9-ms difference between two origin downloads is **not** cache-network benefit. The report now
requires an actual automatic peer hit as well as lower elapsed time before setting benefit true.
All 65 captures / 306 interface records are completely drained with zero drops or forbidden
traffic, the limiter is unchanged and removed, and cleanup succeeds with byte-identical guest
state (SHA-256 `be814e7f2f5d2a2e18973f042ec2970383e82936475a90b93655c727d2bb37bd`).

The [corrected `d0251a27` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34232194290)
and its [full Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34231982302)
**pass**. All five committed checker modules rebuild the complete parent and its HTTPS,
publication, site and adaptive components exactly equal to the report and raw evidence.
The new phase obtains all **3,932,160 bytes / fifteen unique chunks from three providers**, with
zero origin body. Each of R3/R4/R5 supplies five chunks; their actual kernel-timestamped bulk
windows overlap for **106.684345 ms**. The independent original publisher is gone, the Client
cannot read provider stores, and the fresh normal route retains its actual control peer R0,
same Exit and two data relays until explicit disconnect. The complete object hash is the
expected `26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011`.

All earlier native/browser/missing/digest/publication/named/site and later cache-only phases
also pass. Limited Auto chooses the origin in this sample: 6.382 seconds versus 6.325 seconds
OriginOnly and 4.280 seconds PeersFirst, so `automatic_peer_hit` and `benefit_passed` are both
false. No source choice is relabelled to manufacture cache benefit. All 94 captures / 445
interface rows are completely drained with zero drops, truncation or forbidden traffic;
166,432 summed boundary frames are not unique packets. Cleanup leaves zero owned objects and
byte-identical guest state, SHA-256
`09068fcbeb42213c76320b3ecb8643e335d36720b1d414eab23d03666522b68f`.
Artifact ZIP SHA-256: `d825a7bba395dd2ccf7ee8455cb67f865bdb22fc053b89bf96876b75a6722eca`;
canonical parent raw rebuild SHA-256:
`7ff232ca17b5615c08688afb3ecf4a91a1bd673a963a66fe0bc2c48e53efe5eb`.
This is real three-provider missing-content growth, not general speedup, more than two active
MPQUIC paths or a complete expanded-alpha certificate.

### Adaptive HTTPS provider batches

Cooperative-origin and whole-object-digest retrieval no longer reject more than two candidate
providers at the protected writer boundary. Digest index requests use resource-sized batches,
each actual flow taking the same shared lease before route/TLS setup. Completed siblings retain
their input order when another lookup stalls; all pending owners drop before origin fallback.
Compatible original indexes from the complete admitted batch reach the adaptive single writer
together, without changing origin authority, identity, chunks, expiry or the absolute deadline.
Automatic cost prediction prices every resource-limited index batch rather than pretending all
lookups overlap. Unknown costs still prefer the origin; this is not a speed guarantee.

Useful-provider hints now retain a RAM-budgeted recent set rather than two records. The same
sixty-second age and exact route/policy/offer expiry apply; metadata alone cannot create a hint.
One discovery-response batch remains bounded to sixteen candidates, distinct from hint retention
or dynamically admitted active workers. Ten HTTPS tests and four hint/lifecycle tests pass,
including three real simultaneous digest exchanges with independent original indexes and exact
order, a timed-out sibling's cleanup, and source-cost accounting for one/two/three resource slots.
The earlier three-provider native VM does **not** establish three-provider HTTPS delivery;
that expanded live application proof remains pending.

Whole completed-batch cost now complements the conservative individual-provider extrapolation.
The writer retains its existing joined-worker wall measurement only when all sources genuinely
contribute, every close completes, and the batch supplies the entire cold object. Digest retrieval
verifies the complete fresh origin hash before learning the sample. It binds the exact origin
equality key, digest/length, provider set, route/policy, available worker credits and earliest
original offer/measurement expiry. Actual aggregate index setup is counted once before lookup,
then excluded from the predicted remainder after the new lookup has really elapsed. Partial,
cached-prefix, failed or unused-worker attempts cannot teach or refresh this sample;
unknown/changed conditions keep the previous conservative fallback and unchanged twenty-percent
margin. Eleven HTTPS, five parallel-worker and four recent-provider tests pass for this slice.
The [complete `fb86ea62` provider VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34242925635)
passes with exact-source raw reconstruction: the 4-Mbps-origin automatic comparison chooses
two actual peers, receives all 2,097,275 bytes with zero origin body, and takes 4.524811562 seconds
versus 6.631889388 seconds origin-only. This is one constrained-uplink sample, not general benefit
or three-provider HTTPS evidence. Cleanup leaves zero objects and byte-identical guest state.
Artifact ZIP SHA-256: `71b5832033d1fbaa9d80746a690bffd659924329610e35b3aede41701faa2d9f`;
canonical raw reconstruction SHA-256: `de1742fb500b0de157209fc77a8303c118d40ef261d4c81ea674d32f45adc6a8`.

The next fixture adds a cold digest-authorized HTTPS retrieval within the existing R3/R4/R5
three-provider phase. It preserves each original independent index and requires all three
providers, full-object SHA, no origin body, and actual overlapping kernel payload windows.
The old two-provider/Range/reference cases remain unchanged. Four origin-fixture and six
evidence checks, parent reconstruction compatibility, strict example Clippy and shell checks
pass locally; this new three-provider HTTPS network result is still pending.

The [first expanded `78f7125` provider run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34245717172)
**fails before that new phase**, at the earlier ordinary-site evidence check. Both advertised
site replicas contain the complete object, so the adaptive downloader legitimately uses only
R4 for all 2,097,628 bytes / nine chunks, with the correct signed bundle hash and no origin body.
R5 supplies only 1,696 captured response bytes of setup/metadata, not a claimed object share.
The old checker incorrectly required both complete replicas to supply content. The correction
requires a nonempty, unique subset of the authorized replicas, identical actual-source receipts,
and unchanged hashes, exact peer-byte accounting, two WireGuard relay paths and privacy gates.
The later cache-only read still requires zero provider traffic. Four focused checks and the
retained raw site rebuild pass with this corrected checker; the old workflow remains failed.
The separate disjoint-chunk two/three-provider proofs retain their actual multi-provider requirements.
This run's earlier automatic HTTPS comparison chooses the origin, taking 6.34 seconds versus
5.93 seconds origin-only; the previous faster-peer sample is not a universal prediction.

The [next `5b1ba7af` provider VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34838840638)
reaches both three-provider native and HTTPS retrievals. Each reconstructs all 15 chunks /
3,932,160 bytes from three providers with no origin body, but the bulk intervals do not overlap:
the latest start follows the earliest finish by 437.107 ms (native) and 303.425 ms (HTTPS).
The exact raw rebuild therefore reproduces `CONTENT_PROVIDER_ADAPTIVE_EVIDENCE_INVALID`;
complete retrieval is not a concurrent-throughput pass. Cleanup leaves zero owned objects
and byte-identical retained guest state. The next production correction gives an already
admitted exploratory provider first choice of unresolved, previously missed chunks before
established providers refill. This avoids spending a cold probe on unrelated coverage while
its motivating chunk is assigned elsewhere. It does not infer chunk ownership from manifest
membership, duplicate in-flight requests or change resource/benefit thresholds. Five targeted
parallel-transfer checks pass; the unchanged live overlap gate is exercised by the next run.

The [corrected `1aab4caf` provider VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34841784259)
**passes** the complete scenario and independently reconstructed parent/component/raw evidence.
Native and fresh-origin-digest HTTPS each obtain all fifteen chunks / 3,932,160 bytes from three
providers with no origin body. The actual three-way bulk windows overlap by 100.127 ms and
127.542 ms respectively; the HTTPS case retains each independent original index and performs
one fresh TLS 1.3 HEAD, not a full origin GET. The original publisher has exited before the
native fetch and the cold Client cannot read replica stores directly. Whole-object SHA-256:
`26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011`.
The separate fixed-4-Mbps comparison uses two peers: automatic retrieval takes 4.179 seconds
versus 6.386 seconds origin-only, with zero origin body. This one constrained-uplink sample
does not establish a general speedup or a three-provider speed comparison. All 100 captures /
474 interface rows are complete, and teardown leaves zero owned objects plus byte-identical
retained guest state. Five exact-source checker modules reproduce all component and parent
evidence. Canonical raw SHA-256:
`2a39c28a085fcf09961722e2247a81d3a9a750ed82d5abbaf08460ebdf1f7f42`.

### Adaptive mesh-neighbor integration

Wi-Fi configuration now uses zero as the default optional operator ceiling, replacing the
former eight-default/thirty-two-maximum product policy. The normal five-second monitor derives
one-at-a-time new peering admission from actual station progress, resource headroom and real
in-use-channel active/busy survey deltas. Missing survey data permits slower thirty-second
exploratory peering, with an explicit one-time bypass for a silent first acquaintance; subsequent
new stations must actually progress. Missing telemetry is never reported as spare airtime.
Pressure/lower admission preserves current peers. The new typed helper update is bound to the
original runtime/handle and only changes `MESHCONF_MAX_PEER_LINKS` after owned-interface checks,
then verifies ACK and actual readback. The current 512-observation wire/dump boundary still
limits effective admission; no unlimited peer count or physical-radio benefit is claimed.
Eighteen targeted checks pass: four agent admission/Unix-owner lifecycle checks, eleven helper
checks (including six pure kernel cases), two configuration checks and one routing-wire check.
Combined agent/helper/configuration/routing all-targets/all-features strict Clippy and formatting
pass. The absent development-host hwsim module was not loaded.

The [exact `e146b560` simulated-radio VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34238191689)
**passes** on the pinned Linux 6.12.107 kernel. Both original owners read back admission zero,
then two, retain their established peer and exchange 131,072 bytes in each direction with
matching cross-peer SHA-256 values and increasing actual station byte/packet counters.
Normal idempotent deletion and socket-loss cleanup pass. The executed guest script compares
its original network/namespace snapshots and reports zero owned objects plus unchanged state;
those temporary snapshots are not exported, so independent retained-byte comparison is unavailable.
The raw owner logs preserve admission -> payload -> removal ordering. This is real kernel
behavior on two simulated radios, not full-agent adaptive growth, large-mesh throughput or
physical-radio proof. Artifact ZIP SHA-256:
`301c535bc313a3b773869de381c3d81c4c1bb648fd0a6396e444df22b9ca2af5`.
The exact committed checker reproduces the owner/admission/payload evidence and report;
canonical report SHA-256: `99c234f73e39cc54ed753f8deee80e86f2859586648ef003b71509df033c8d3b`.

### Adaptive control-connection admission

The production discovery actor now replaces its bootstrap established-connection ceilings
before normal/mesh initial dialing and on the existing one-second maintenance tick. Either
direction may consume the resource-derived total rather than stopping permanently at 384 total
or 256 inbound/outbound. Existing protocol demand initiates real connections; this change does
not speculatively dial to fill the allowance or count control contacts as additional payload paths.

The shared, read-only RAM/cgroup/descriptor/PSI sampler preserves the previous content-worker
policy. Control admission independently budgets additional one-MiB/four-descriptor units from
1/32 of free RAM and one quarter of free descriptors, less pending handshake units. Pressure
reduces only additional room sixteen-fold; unknown RAM/FD headroom permits no new established
connections. Neither resource loss nor a lower ceiling closes an existing connection. The
provenance registry retains every previously admissible live/queued lineage without bulk
preallocation or changing its generation. Pending/per-peer/address-cache input guards remain.
This is advisory admission, not immediate eviction, bandwidth benefit, a kernel reservation,
physical Wi-Fi proof or a replacement for native transport path ceilings.

Eight targeted checks pass: three control-budget cases, the shared kernel-parser case, two
unchanged content-lease cases, and two discovery capacity/provenance cases. The real isolated
MemoryTransport test establishes 385 incoming Noise/Yamux control connections after a live
budget update, exceeding both old ceilings; setting admission to zero rejects a new connection
without closing those 385 or invalidating the original binding. An exact subsequent close
retires only its own lineage. A separate queued-event test preserves the original public-prefix
witness across lowering and verifies no allocation proportional to the ceiling. Strict discovery
and agent all-target/all-feature Clippy and formatting pass. This is authenticated local control
transport evidence, not WAN throughput or 385 payload routes. The `d0251a27` provider VM above
also passes with this production actor, but its small topology does not establish 385 WAN peers.

### Warm MPTCP growth integration

The complete reserved proof set now travels separately from the canonical initial-active
subset in MPTCP session start and its exact echoed signal. Client and Exit initially join only
that subset; the kernel's permitted room includes the already authorized warm paths. Every
initial path remains available to other flows sharing the route.

The production Exit samples its existing authenticated MPTCP/TLS flows once per second using
`MPTCP_FULL_INFO`, without cloning descriptors or querying the privileged helper. Observations
bind kernel subflow lifetime, exact route tuples, ACK/receive counters and actual retransmission
deltas. Sustained loss can add one reserved SIGNAL endpoint; an extra probe may later retire
when unhelpful, but only while every known live flow retains its initial established set.
Unknown observations grant no extra admission or retirement. Kernel scheduling and reinjection
are unchanged; transport ACK bytes are not presented as unique application throughput.

The real disposable kernel test observes two subflows carrying a 65-MiB transfer, with stable
identities, monotone counters and more than 512 KiB acknowledged on each. Twenty targeted agent
tests and strict agent Clippy pass. The new `mptcp-growth` scenario must still prove one real
download growing from two to three simultaneous data-carrying subflows with six WireGuard legs,
the complete payload hash, normal disconnect and unchanged guest state. No live three-subflow
growth, arbitrary path count or throughput improvement is claimed yet.

The [first `5b1ba7af` MPTCP growth VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34838837544)
fails at `mptcp-growth-sustained-download-loss` with
`MPTCP_GROWTH_FLOW_ENDED_BEFORE_GROWTH`. It does not prove live three-subflow growth. The retained
report records complete cleanup and zero owned objects. Its controller does add and retire the
warm endpoint three times, but the actual application half-close sends MPTCP DATA_FIN before
the response completes. A separate disposable kernel reproduction confirms that subsequent
SIGNAL endpoints can create new subflows while ESTABLISHED, but not after that half-close.
The corrected TLS adapter retains authenticated `close_notify` as directional application EOF
and defers underlying transport FIN until the complete flow closes. A real isolated MPTCP/TLS
test retains both original negotiated metasockets without transport EOF, transfers a full 1-MiB response after request
EOF, closes both descriptors on drop and still rejects truncated TLS with `UnexpectedEof`.
The evidence checker also uses the actual helper-ingress address `169.254.240.1`, not the
Client's public underlay address. Two TLS checks and six checker tests pass. Neither these
local results nor endpoint-add notifications replace a live three-subflow proof.

The subsequent Ubuntu Quality run on `1aab4caf` reaches this test but its namespace-wide
`ss -M` observation returns no sockets. The portable regression instead observes read-half-close
directly on its two owned MPTCP descriptors, binds their inode/address identities, and includes
a real `SHUT_WR` negative control that must produce kernel read-half-close at both ends.
Subflow `TCP_INFO` state is not substituted for MPTCP meta-state, and no test privileges or
production transport behavior are broadened by this observation change.

The [corrected `1aab4caf` MPTCP growth VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34841782480)
**passes** that live proof and independent exact-source report/raw reconstruction. The original
Client/Exit metasockets and initial subflow lifetimes remain unchanged while one 32-MiB download
grows from two to three simultaneously carrying subflows. Fresh Exit ACK deltas are
78,384 / 378,872 / 389,438 bytes and Client receive deltas are 78,384 / 392,072 / 392,078 bytes
over the same 439.510-ms interval. All six WireGuard legs carry data. The selected owned leg
records 184 actual netem drops and 177 additional TCP retransmissions; no synthetic health
notification substitutes for those observations. The full response hash agrees at both ends:
`08b53098cfa4dbb71d16a27d93879734ed118a7041484c797dddc6d27bfabd3d`.
All ten captures / 52 interface rows are complete. The original flow disconnects, contexts and
paths empty, injected limits disappear, and zero owned objects plus byte-identical retained
guest state remain. Three exact-source checker modules reproduce the evidence. Canonical raw
SHA-256: `14fe6bddfa15a9a3aa1155c09361737691c746f83d41ee70cfe3add404e595f1`.
This is bounded live growth, not a controlled speedup comparison or removal of the backend cap.

### Warm MPQUIC growth integration

The browser-route owner can now activate an exact retained warm descriptor without first
removing its existing carrying paths. Two successive health observations with fresh transport-ACK
progress on every active path and sustained loss on one justify the bounded failover probe.
Growth is N -> N+1 rather than special-cased to two paths. Native `AddPath` retains the original
context/Exit/grants and signed minimum; a Ready reply alone does not prove the added path carries
bytes. Later native deltas must demonstrate actual contribution. Without continuing failover
value the added path retires after the existing ten-second grace; a stalled weak path can instead
retire once the others really carry data, never below the signed minimum. The controller does
not infer unique application bytes or throughput gain, or change the backend eight-path cap.

Path-health maintenance now has its own joined one-second task, independent of the existing
thirty-second policy refresh. It skips missed ticks rather than overlapping calls, stops before
route teardown and checks current policy/client-role ownership before native work. The new
`mpquic-growth` scenario uses ordinary discovery and reservations for two active plus one warm
R0/R1/R2 path, with bounded retries rather than a production selector override. Its real HTTP/3
fixture sends 32 MiB each way without artificial application sleeps. Fixed 15% loss on one owned
Relay exit-facing veth must cause live growth; fresh three-path counters and physical captures
must then prove all six WireGuard legs, followed by exact payload hashes and complete cleanup.
The scenario is separate from A01–A15 and throughput comparisons. Its first exact-source VM
result is recorded below; injected health tests and an executable fixture do not make it a pass.

Local verification passes: two growth lifecycle cases, two independent-cadence/shutdown checks,
the existing warm replacement and policy/role-revocation regressions, and strict agent
all-targets/all-features Clippy. The HTTP/3 case/profile test and strict example Clippy pass.
The wrapper's static contract, non-mutating previews, syntax and warning-level ShellCheck pass;
three pure evidence checks also pass. One disposable user/network namespace accepts the exact
15% netem JSON profile and restores its owned veth to `noqueue`; that schema/cleanup check carries
no payload. These local checks are not live MPQUIC payload evidence.

The API7 follow-up passes 29 focused Rust checks across wire/FD bindings, exact native status,
counter rollback, health projection and three growth cases, including four-to-five with a signed
minimum of three. Three native C protocol/runtime/binding checks and joint strict Clippy for
quic/agent/local-control/CLI pass. The evidence parser rejects missing ACK counters and does not
substitute user bytes. These checks do not establish live three- or five-path growth.

The [first `fbd070aa` growth VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34234984155)
**fails at selection**, before HTTP/3, loss injection or payload captures; its separate
[Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34234801937) passes.
The last native snapshot contains two active paths through R2/R1, but not the required reserved
warm row. Normal contexts did establish and disconnect during bounded retries, so this is not
evidence that all connection attempts failed. Source diagnosis identifies an impossible fixture:
only R0/R1/R2 advertised at least the Client's required eight Mbps, and the genuine selector
excludes its separately chosen control Relay from data paths. Three eligible Relays therefore
left at most two data candidates, never two active plus one warm. Warm retention and CLI
projection have no demonstrated bug here. The scenario-only correction gives existing R3
sufficient advertised capacity and a real Exit bootstrap contact over its already present link.
Normal selection, distinct-control rules and bounded retries remain unchanged; no particular
draw or successful growth is manufactured. The corrected live result is recorded below.
No three-path payload proof was reached on `fbd070aa`.
Global disposable cleanup reports zero objects and byte-identical guest state, but the Client
log separately contains `SHUTDOWN_CLEANUP_FAILED`; that is not a clean-agent-shutdown result.
Artifact ZIP SHA-256: `258fcb219e0da713a3b3ad5cbbd3bd45b967507dc967b6104c8f9727574de8b7`.

The [corrected `32b985ba` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34238873161)
**passes selection but fails before loss injection**: it obtains two active native paths and
one genuine warm row, then the progress gate observes zero `delivered_bytes` for 68.465 seconds.
The five complete initial captures show traffic on both WireGuard legs of both active relays
and at the destination, with zero drops/forbidden traffic. This is not a failure to start networking,
but no complete application receipt/hash or three-path result was reached.
The exact native source intentionally exports zero unique-inner `delivered_bytes`; it already
has acknowledged transport bytes but previously exposes only their nonzero boolean. The growth
controller/checker consumed the wrong measurement. API7 adds a separate explicit transport-ACK
counter instead of relabelling transport bytes as unique user bytes.
Cleanup leaves zero owned objects and byte-identical retained guest state; this run has no
Client shutdown error in its empty Client log. Its [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34238544971)
passes. Artifact ZIP SHA-256:
`b5c27e689c53fe71fd184578ea7d2d2484ec0aab08551b66c8e995f07e469990`.

The [API7 `fb86ea62` growth VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34242922200)
passes the initial two-path ACK-progress gate, but **fails** with
`MPQUIC_GROWTH_THIRD_PATH_NOT_ACTIVE`. Both native counters continue forward for 90.074 seconds
under the installed 15% loss profile, while the original warm path stays unused. Final counters
are 5,000,460 and 31,470,964 acknowledged transport bytes; user-byte counters correctly remain
zero. There are no final application receipts or three-path proof. The retained cleanup qdisc
shows the installed profile but lacks drop statistics; sequential internal health observations
were not logged, so a controller cause is not yet established. The follow-up enables only bounded
owned-path counter/decision diagnostics in this disposable scenario and retains qdisc statistics
even on failure; it does not relax growth conditions.
Artifact ZIP SHA-256: `898b3bbe2c9f722057c3e5c7d4accb67ddc4b084224fc72c3021c369ebe7e3b3`.
The same-source [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34242594444)
passes strict Clippy/workspace tests but fails its static harness check on a changed comment's
literal wording. The obsolete comment grep is removed; executable ACK-versus-user-counter
assertions remain in the benchmark checker test.

The [diagnostic `78f7125` growth run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34245714141)
also fails: an owned netem qdisc drops 1,510 packets, while ten native samples and 93 route-health
observations still report zero loss. The route eventually replaces an initial path rather than
keeping three active paths. Source inspection identifies the mismatch: xquic's `ctl_lost_count`
tracks lost packets subsequently retransmitted, whereas these unreliable MASQUE datagrams are
not retransmitted by that transport. The corrected mapping uses a separate 64-bit, path-lifetime
detected-loss counter at the actual loss-declaration site. Its native regression invokes the
real xquic detector: one unreliable datagram is lost with no repair queued, the old counter stays
zero, and the new exported counter becomes one exactly once. Crossing 32 bits and saturation
are covered. No growth threshold changes or live three-path success are claimed; the corrected
network run is still required. The [same-source Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34245544220)
passed. GitHub's aggregate CodeQL findings gate remains open separately; this is not a release
security clearance.

The [corrected `5b1ba7af` MPQUIC growth VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34838838851)
**passes**, including an exact-source independent report/raw-evidence rebuild. One HTTP/3
connection grows from initial active paths 1/3 to simultaneous paths 1/2/3 without changing
its route context or Exit. During the owned 15% loss profile, netem records 122 actual drops.
After expansion, the three transport-ACK deltas are 97,188, 301,532 and 94,696 bytes; these are
not reported as unique application bytes. Retained boundary captures show data on all six
WireGuard legs without forbidden packets or capture drops. The application sends and receives
33,554,432 bytes, with matching independent client/server hashes in each direction. Both
applications exit successfully, the loss qdisc is removed, route/context counts return to zero,
and retained before/after guest-state files are byte-identical. This completes the bounded live
warm-growth proof, not a throughput comparison, arbitrary path-count support or the expanded
alpha. Artifact ZIP SHA-256:
`4ef47461dcde1b2007ba55244c4a9c907db0e239b7c9ca02aabd04b5eba5e833`.

### Native publication/site cache-only reopen

`content fetch-name` and `content site open` now accept explicit `--reuse-cache --cache-only`.
A completed normal named retrieval retains its original public-native signed envelope beside
the existing durable revision floor, bounded to 64 names in the same owned cache. Reopening
uses the caller's independently trusted publisher key, exact name/minimum revision, original
signature/expiry and complete object hash. Missing chunks, an expired manifest or a higher
observed/conflicting revision cannot silently return an older snapshot or trigger a network
fallback. Old chunk-only caches need one normal successful retrieval to acquire an envelope.

The cache-only agent branch performs no route preparation, discovery, origin retrieval,
contribution enqueue or post-download incidental uptake. It retains the client-role/local-socket
boundary but does not require an Internet policy to read already authorized local native bytes.
The normal network branch's policy checks remain unchanged. Ready echoes the exact source mode;
the CLI rejects network/provider accounting in cache-only receipts. The existing site viewer
keeps its isolated localhost behavior and original signed expiry. Separately configured running
agent services are not stopped by this per-operation flag.

Two real disk/reopen tests pass, including original-envelope preservation, floor-before-snapshot
rollback refusal, durable conflicts, expiry, missing chunks and bounded private storage. Three
agent named tests pass, including actual local chunk transfer from a reopened complete store.
Five isolated CLI-process tests, two wire tests and two parser tests pass; scoped content and
joint agent/CLI/local-control Clippy also pass. The CLI site fixture exercises HTTP retrieval,
not a browser engine or a live production-agent topology. The additive real-agent no-route
site-reopen network proof is ready; three site and fourteen parent checker tests pass with
narrow shell checks. This is local native availability, not completed
external retention repair, reusable HTTPS authority or globally latest-version assurance.

The [exact-source cache-only run on `4e6cc308`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34214732165)
now **passes**, including report equality with a full independent raw rebuild using that commit's
archived checkers. After real route disconnect, the same agent cache (`65025:27641`) supplies
2,097,628 bytes / nine chunks, SHA-256
`5e3012170ca5335e4f8b7e419fda3ae4ddf59e7603eeabb6a9c2544ea6088a04`.
Before and after the operation, connected is false, contexts/MPTCP subflows/MPQUIC paths are
zero and paths are empty, with no new content-discovery/provider events. The receipt reports
zero peer/origin bytes, zero providers and an empty control ID. All four assets, HEAD, the
4096-byte Range, denials, listener shutdown and private-spool cleanup pass; no browser engine
was executed. All seventy captures / 332 interface rows are complete and zero-drop; the six
cache-only captures contain no WireGuard data or provider-application bytes. Cleanup leaves zero
owned objects and unchanged guest state, SHA-256
`91d43353558052eb03c33a713f03e6dffa8d4c49e9ff7482b2a8570ea9daefc3`.
Artifact ZIP SHA-256: `64acd2860ee4c22ec568d72b178956e80d345e61fa73d0a2ce4d7ef56d40fbb9`;
canonical raw rebuild SHA-256: `eaf112701f4dbee3ec362e91752111857ac7a97e5dc12daef246ca7df2a4e9c4`.

The [separate `4e6cc308` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34214662839)
**fails** in `route_snapshot_alternative_controls_keep_one_exact_signed_exit_and_affine_subjects`
with `InsufficientDiverseRelays` (497 agent tests pass, one fails). This does not invalidate the
independent site proof or turn the broad run green. The unchanged route fixture lets an Exit's
random nonce discriminator collide with one of three fixed relay network discriminators
(3/256 possible first bytes); that provides a reproducible explanation, not knowledge of the
unlogged original CI nonce. Forcing the collision reproduces the exact same error in 0.23 seconds;
the same pinpoint test passes in 0.23 seconds with the fixture Exit discriminator fixed to 43,
outside relay discriminators 40–42, while retaining its other 31 random nonce bytes. Formatter
and diff checks pass. Product selection/diversity code and all existing test assertions are
unchanged. The original failed run remains failed; the new commit still needs its own full CI.

### Automatic contribution startup/restart checkpoint

The new explicit `content_contribution` configuration binds one cache, endpoint and quota to
the agent lifecycle. It requires relay participation and configured upload/download accounting;
installation defaults remain inert. A listener may start empty but advertises only usable
restored/admitted content. Completed native, named and freshly authorized cooperative HTTPS
downloads enqueue bounded storage-only copies, with no URL or reusable HTTPS authority saved.
The background queue, existing incidental-uptake job and foreground cancellation share one
cache owner and budget. Public replicas retain their original signatures, expiry and bounded
journal; private-message and mailbox content must not enter automatic public redistribution.
Two library store/duplex tests, three new runtime tests, two existing replication-runtime tests,
all thirty configuration tests and strict content/agent/config Clippy pass. These include actual
incremental storage and re-serving after reopen, quota without eviction, private-v3 admission
rejection and refusal to promote a legacy private journal. Expiry tests use explicit library
time; the newer source-bound network result below supplies the live agent-start proof. Seven
initial additive harness/checker tests, shellsyntax and strict ShellCheck pass. The dedicated
VM requires an initially empty automatic service, ordinary P download, original-node shutdown,
a real agent PID change with retained journal and independent protected P retrieval. This is not arbitrary HTTPS
interception, retention repair or globally fair placement.

The [first automatic-start VM on `24e9a4b9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34209702866)
**fails before automatic startup**: the test calls `restart_advertiser`, which is defined only
inside the skipped A01 scenario block. The existing P/Q transfers, owner-contention interval
and ten complete zero-drop captures pass independently, but provide no automatic-start proof.
Cleanup leaves zero owned objects and unchanged guest state. Artifact ZIP SHA-256:
`63cbcc758e44fafb32dd57514531f8b749b16737498ab2215083c2678bb5a5d8`.
The replication script now performs its own bounded restart of the already owned R4 unit,
retaining PID/namespace/executable and journal checks. Eight narrow checker tests and strict
shell checks pass; the standalone dependency regression performs no host service operation.
The [corrected network run on `f76ac97a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34211580709)
now **passes**, including an independent rebuild from the complete raw artifact. R4 starts
with zero publications/chunks/bytes, admits a normal P download into three chunks / 524,609
bytes, and publishes one usable object. The original R5 provider stops (inactive, PID zero,
listener absent). R4's agent PID changes from 18565 to 21526 in the same namespace, preserving
cache inode 27282 and its exact 624-byte journal. An independent Client then retrieves every
P byte from R4 alone through a new protected context with R1/R2; the earlier uptake used R0/R1.
P SHA-256 is `507a1f72e20863b91dbd92265ad6d58499cc16fab5a9d753676c56bbe87cb836`;
unchanged journal SHA-256 is `9df829ad50804c734151c996950acfb6d0ee74d1cd35628b1225fb40db0cf44c`.
All twenty captures / 156 interface rows are complete with zero drops or forbidden packets.
Cleanup leaves zero owned objects and identical guest host state, SHA-256
`f3a2de8a8a0053d1a98e7fcba7f2ffbd274545ec86a93cc379e4bad7a90809ad`.
Artifact ZIP SHA-256: `0091da2ebbc4252c86c753523ff17b4e7702a3204869d2e12e8218102bf34599`;
canonical raw rebuild SHA-256: `6aa3ef51114bb65d1e4799bcd48f7593fa3080ecea5405d634f0417c088b7864`.
The older failed run remains failed. The
[Quality run on the original `24e9a4b9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34209675968)
passes independently of that scenario failure; the subsequent `f76ac97a` Quality run was
cancelled after a newer push, not passed or attributed to a test failure.

## Latest known-contact mailbox integration checkpoint

The new normal `content mailbox` path implements explicit invite, two-provider enrollment,
encrypted deposit, private inbox discovery without a caller-supplied message manifest/ID,
retrieval/local decryption and acknowledgement. Original invitations bind independently trusted
contact/provider keys, quotas and expiry. The provider uses its existing signed identity and
protected content endpoint, not a new central service; application keys stay with the local CLI.
Every operation binds a fresh provider-signed connection challenge to its exact invitation and
object. See the [commands and limits](OPERATIONS.md#known-contact-mailboxes) and
[wire contract](PROTOCOL.md#known-contact-mailbox-operations-development-v1).

Three actual disk-store tests pass, including reopen/HPKE delivery, quota refusal, expiry,
acknowledgement tombstones and corrupt/foreign cache rejection. Two authenticated-stream tests
pass: two stores accept a deposit, both reopen without the sender's manifest supplied to the
recipient, then private listing/Get/decryption/Acknowledge completes; connection/provider/grant
and operation substitutions fail. Strict content-crate Clippy passes. These use real cryptography
and filesystem stores but in-process transport, not protected-network packet evidence.

Fresh exact provider lookup also passes a four-swarm disposable-namespace libp2p test: the broker
learns an initially unknown provider via Kademlia, both actual signed offers reach the Client,
and the Client makes zero direct provider connections. Withdrawal fails closed. The exact codec
test and strict discovery Clippy pass. The agent's signed-grant/provider/typed-operation test and
combined agent/local-control/CLI strict Clippy also pass. Two real CLI-process tests run in
capability-dropped disposable namespaces: they delete the sender identity, input and manifest,
reopen both providers, discover/Get/decrypt/acknowledge the inbox, check private output and
no-clobber, reject wrong identities and mismatched final responses, and exercise one-provider
List failure with explicit degraded readout. Those providers use the real store/protocol behind
Unix/duplex streams, not the production network. The CLI parser test passes. The first protected
network result and its distinct checker failure are recorded below. Those local tests alone do not
prove network C07, automatic contact discovery, retention repair, speedup or global offline availability.

The additive `content-mailbox` KVM scenario is now executable: two independent provider agents,
normal invite/enroll/deposit, sender application keys/input/manifest removed, normal Disconnect,
one provider store stopped/reopened, then private listing/Get/decryption/two acknowledgements
and an empty repeat on a fresh protected route. Two application identities share one Client
agent; this does not claim an independently offline sender node. It requires two real MPTCP
relay paths, both providers' signed receipts, complete physical/control captures and unchanged
guest cleanup. Its source-bound checker and shell/runner contracts pass locally.
The [first exact `d1fd6d1f` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34191416065)
completes the actual sequence: two providers retain the 2,097,332-byte ciphertext, the sender's
keys/input/manifest are removed, one store reopens with the same inode, and a fresh receiving
route retrieves/decrypts 2,097,275 bytes without a manifest/ID input. Both signed acknowledgements
are present; a repeated inbox is empty. Plaintext SHA-256 is
`add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
Four send and seven receive MPTCP Exit flows complete; all ten physical and two control capture
windows are drained, zero-drop and free of forbidden packets. Cleanup leaves zero owned objects;
raw guest-state files are identical, SHA-256
`fc1509ab8ac8456b91548347b7e5dd02af59d2ea0a493ee406c85cfd249c6794`.

The workflow nevertheless **fails** at its final checker: `prost::Enumeration` defaults to the
first variant, `Register = 1`, so canonical Register receipts omit tag 3. The checker wrongly
requires that field. The `d19e0d82` checker correction accepts its omission and rejects explicitly
encoded default 1; no signed bytes, runtime validation or privacy gate change. Both checker tests
and a complete rebuild from the original raw artifact pass. Original ZIP SHA-256:
`214e1eb7145cf65c6013dec9e11611c85c4eabb37f4cfb65199b1e6f800d7ac7`;
corrected raw-evidence rebuild SHA-256:
`a8aa78f7271ad1f5d9849c043ef1f3757726f793da8a988ec10dc5147b4faaf7`.
The historical workflow stays failed; the
[fresh mailbox run on `b172d11f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192823996)
now **passes**, including an independent exact-source checker/raw rebuild equal to the original
report. The sender application exits, its secrets/input/manifest are gone and its route is
disconnected; the intended owner receives on a fresh route from the reopened provider, verifies
the same plaintext hash, acknowledges both copies and sees an empty repeat. Eleven MPTCP flows,
all twelve complete zero-drop/forbidden-packet-free captures and zero remaining owned objects pass.
This satisfies C07's stated sender-exit criterion using two application identities behind one
Client, without claiming an independently offline sender machine or permanent availability.
Original artifact ZIP SHA-256:
`ec7765e1fb4a1278a81ea4a0e1edcc9aa2b36fe798a421f1a437c8e16e814eef`;
byte-identical raw guest-state SHA-256:
`1ae5faca21180235c4ff1dbfa5c35eae8a913582646748329aae9e65dfe8c99b`.

The [initial `891f86f5` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34190575234)
stopped at formatting because the new mailbox/manifest module declarations were out of order;
that two-line ordering is corrected without changing behavior. No full Quality pass is claimed.

## Latest DNS integration checkpoint

The positive DNSSEC cache is now composed into the normal agent: the same bounded RAM resolver
serves protected DNS, TCP resolution, general UDP and browser-QUIC destination pinning. Its peer
backend uses signed, bounded cache-only RPC and a generic provider capability, not DNS names in
the DHT. Complete control/data-relay exclusions come from the verified reservation and survive
detached TCP ownership; ambiguous provenance disables peer requests. No roles, root anchors or
host resolver settings are changed automatically. The
[configuration and fallback rules](OPERATIONS.md#shared-positive-dns-cache) are documented.

The existing exact Hickory version now enables its ring DNSSEC backend, with the recorded NSEC3
backport and unchanged vendor/license verification. A real cryptographic root/DS/child/A+AAAA
test chain, monotone TTL/replay bounds and disposable TCP collector pass; test trust anchors are
private `cfg(test)` seams, never product configuration. Combined all-target/all-feature compile
and strict Clippy pass for agent, Exit, config, UDP, discovery and protocol, including the
fixture-only `dns-cache-proof` executable. That executable accepts only an explicit loopback
recursive fixture in a different network namespace and requires genuine built-in-anchor A/AAAA
validation plus local cache reuse; an OS fallback can never count as its success.
The signed protocol and codec tests, two actor/exclusion tests, verified Exit-scope test, all 28
config tests and exact schema check pass. The actor executes inside a disposable namespace and
proves a signed cache miss without triggering an upstream lookup, not a positive peer hit.
The bounded public-wire recorder/replayer and preflight runner have four socket-free evidence
tests and shell checks passing. The source-bound
[public-chain preflight on `0fa80d65`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34182008684)
now also passes: fresh unmodified public `iana.org` A and AAAA answers validate against the
unchanged built-in roots, each reports `UpstreamValidated`, and each repeats from `LocalValidated`
cache. The answers are `192.0.43.8` and `2001:500:88:200::8`; both had 969 seconds of remaining
validity during this run. Original public wire records, source/binary hashes and collector output
are retained in artifact SHA-256
`4efa632e5ea53462b7c16cfda30ddc9eca935a183a8d2aeea1a077aa586ff857`.
The replay listener closes cleanly. This is a real public-root collector/local-cache pass,
not a normal Client route or positive peer-cache pass. A fresh
[repeat on `73c0c4be`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34185235916)
also passes both families and local reuse with unchanged roots. The preceding `1024e6d2`
standalone run failed while collecting public data, before validation; its generic `ValueError`
did not retain the cause. The recorder now preserves fixed local rejection reasons (five focused
checks pass), without changing acceptance, trust or TTL rules. No cause is inferred from the repeat.
The normal resolver now exports only aggregate local/peer/upstream/fallback counters through the
existing loopback-only metrics endpoint, plus signed cache-miss replies queued by the actor.
No names, addresses or peer labels are added. Targeted cache/source-accounting, actor, metrics
and exact development-policy flag tests pass. The GitHub preflight builds before collecting the
expiring public records and uses the same capability-dropped namespace runner.

Before the `b172d11f` pass below, the ordinary two-Exit upstream/peer/local-hit/fallback sequence
remained unproved. Its disposable `dns-cache` scenario uses fresh original public
wire records, normal protected requests to each selected Exit, seven source-accounted phases,
peer shutdown and 35 physical capture windows. Four checker/classifier tests, four existing
public-fixture tests and shell/topology-contract checks pass; these are not a live peer-cache pass.
Its [first `1c9c759d` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34183233474)
fails during preflight, before the normal DNS phases. Public wire collection succeeds, but nested
validator diagnostics were not exported. Source review finds the replay script still under the
`vpci`-owned private checkout, unreadable to capability-dropped root; the binary was already
correctly staged. The fixture now stages script/replay/runner together in a root-owned tree and
retains bounded nested diagnostics. No DNSSEC root, signed record or TTL rule is loosened, and
the correction still needs a new live run. Cleanup leaves zero owned objects and raw guest state
unchanged, SHA-256 `dc55803ed7a7fb55413bf488dbb6b3fa7a98e4179b34f8007bea64e72e459cec`.
Artifact SHA-256: `9e0e9d67392ea71ab159a637503d63e4f2c63fe963b5a1d6bdb764ec56a39ba0`.
The [next `1024e6d2` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34184628720)
stops earlier, before collection: cold discovery consumes 120 quarter-second admission attempts,
ending with `PRESELECTION_OWNER_BUSY`, no selected route and no DNS request. The fixture now uses
the existing topology's one-second admission cadence within its original 180-second deadline;
this does not retry failed DNS queries or prove that route setup succeeds. This run also cleans
up completely with unchanged raw guest state; artifact SHA-256
`334fdf8d1680297d4e2803db0fc422982e84357e0bb2f76f249981278215c693`.
The [paced `7f36438d` run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34185521557)
does select a real route and passes the staged, capability-dropped public-root preflight for
both families, including local reuse with 356 seconds remaining. It then fails the first normal
protected A request (`DNS_CACHE_PROTECTED_APPLICATION_FAILED`); no positive peer-cache pass is
claimed. Cleanup is complete with zero owned objects and unchanged raw guest state, SHA-256
`2b6f3c3bc3611255cfa16bfcb1d792b1a8c039e72f1a788fbf0515f7c92909fe`.
Artifact SHA-256: `2e568572744980b81a006bd54bbd3a942dd9c5ed6c9c6ccf8c9c0af0d35643f9`.
Source tracing identifies the first-request failure: ordinary UDP and protected DNS shared one
route controller. The fixture's native `single-path-udp` prewarm occupied it with `NativeUdp`,
while DNS requires `UdpReady` and waited until its request timed out. The agent now gives UDP/TCP
DNS their own bounded controller; main data/content ownership stays separate. The normal typed
`connect --transport protected-dns` prepares the actual DNS association, with an exact context/
Relay/Exit projection and honest zero-byte `Reachable` state. Retirement clears that exact context,
including its embedded owner; maintenance, policy/client disablement, Disconnect and shutdown
include both controllers. UDP/TCP DNS and explicit DNS preparation share a bounded transaction
gate, preventing a competing query from retiring another query's active association while leaving
the main route independent. Seven focused DNS/controller/wire/CLI tests, six control tests and
the CLI command-form test pass, along with strict all-target/all-feature agent/local-control/CLI
Clippy. Four DNS network-checker tests, five original-wire fixture tests and shell checks also pass.
The C05 harness selects this actual DNS route separately for every
request and keeps all answer, source, original-root/TTL, capture and cleanup gates. Its new live
result is pending, and simultaneous main-data/DNS packet delivery is not claimed from unit tests.
The [exact `4f90e370` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34187656229)
now passes both ordinary warm DNS requests: A via Relay2 (42 response bytes, 593 ms) and AAAA
via Relay1 (54 bytes, 554 ms), each over one real two-leg WireGuard route. ExitA reports exactly
one `upstream_validated` answer per phase and no peer/local/fallback increment; each collects
six original public-chain records. All ten physical captures are complete, drained and free of
forbidden packets or socket drops. The original-source phase validator passes on the raw records.
The overall run still **fails** before the first peer request: route setup selects Relay1 for
Exit2, but the original fixture only provides Relay0--Exit2 connectivity. The scenario now adds
real Relay1/Relay2--Exit2 links and exact return routes, excludes their private addresses from
the Client, and requires their actual interfaces in capture accounting. Selection, timeouts,
DNSSEC roots and privacy gates are unchanged; this correction still needs its new live run.
Cleanup leaves zero owned objects and raw guest state unchanged, SHA-256
`b43c60da6762c1f52f856340e06e15c6717083d0f7f84670588f4ab92a78f6d3`.
Artifact SHA-256: `abe005c73a69bccf7cf1b072db018903b6290e68d141ae9913e5a7384ff5c7c6`.
The [subsequent exact `5ac9bb0e` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34189965926)
passes warm A/AAAA again and now reaches Exit2 through Relay2, with 56 WireGuard data datagrams
on each leg. The ordinary A query returns 42 correct response bytes in 564 ms, but Exit2 reports
`TrustedFallback +1` and `PeerValidated 0`: the run correctly fails with
`DNS_CACHE_EXPECTED_SOURCE_NOT_OBSERVED`. Later peer/local phases were not run. The precise
peer-selection/response failure is not yet observed, so no timeout or TTL cause is inferred.
All 15 required role captures validate as complete/drained with zero drops or forbidden packets;
cleanup leaves zero owned objects. Raw guest-state files are byte-identical, SHA-256
`0cef40bb226a7c3151fbc5d404392ec7c30809becc7b9260da49912c0c08852d`.
Artifact SHA-256: `dc105e10a2d8557ecaa28b140cd45482fe1154e6d3955301d87740b7825effd4`.
The `d468069` signed-RPC correction now selects and retains the actual authenticated direct
connection instead of refusing every peer with two current connections. A real disposable-namespace
actor test fails before the correction and passes afterward: two concurrent RPCs use two distinct
authenticated connections, and a validly signed response or failure on the wrong sibling cannot
consume the pending request or replay state. Exact peer, connection, request ID and signed request
hash remain bound. Three actor checks, four adapter checks, the codec test and strict agent/discovery
Clippy pass. This reproduces and fixes the two-connection boundary, not an exclusive explanation
of the older VM or a positive peer-DNSSEC proof. The
[new exact `b172d11f` DNS VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192821990)
now **passes** all seven normal protected-query phases. Warm A/AAAA each increment only
`UpstreamValidated` and perform six original-chain TCP queries; ExitB's A/AAAA each increment only
`PeerValidated`, with no upstream or fallback. Unsigned B increments only fallback while the peer
serves a cache-only miss without upstream traffic. After ExitA is inactive/PID 0, both B requests
increment only `LocalValidated`. Every positive answer precedes the original proof expiry.
All 35 captures / 224 interface rows reconcile intake, drain and kernel packet counts with zero
drops, forbidden traffic or direct Client--Exit packets; cleanup leaves zero owned objects.
Original ZIP SHA-256: `0659758928c34a335f4fb04f61de87ed436b76a58750d9a657a7d47f01d9a042`.
Raw guest state is byte-identical, SHA-256
`b6af943e78788602c5909b595ea1906a9c7da494ef9138e96b19db8252e0f2c3`.
The exact-source report and full raw rebuild pass independently. This satisfies C05 with unchanged
roots, TTLs, relay exclusions and source accounting, not arbitrary-answer sharing or speedup.
CNAME/negative-answer
sharing is not implemented; unsupported proofs use the existing resolver without sharing that
result as DNSSEC evidence. No peer-speed improvement or absolute global TTL-replay prevention
is claimed. The older content VM successes below do not verify this newer DNS-integrated build.

The empty-cache advertisement defect identified by the private-message run is now corrected
locally: DNS capability publication requires an actual unexpired RAM proof for the currently
active policy. A cold pure Client publishes no cache offer; expiry, policy change and RAM reset
withdraw the local offer. One real signed-proof availability test, two isolated actor tests and
strict agent/UDP Clippy pass. The C05 fixture waits for an actual Kademlia publication completion
after warming A, not a fixed delay. Already propagated or in-flight DHT hints can still be stale
and cause a dial; no complete recall or general combined-role unlinkability is claimed.

## Latest content integration checkpoint

The explicit `content browser-download` bridge (`91608a97`) is integrated locally: one parser
test, three real CLI-process tests and strict CLI Clippy pass. It exposes only one temporary
localhost attachment after complete cooperative-origin verification, bounded by original authority
and five minutes; no real-browser/VM result, measured benefit or completed C08 is claimed.

Replica admission (`ba48fce5`) now waits for owner traffic to settle before the next chunk credit,
then resumes the same bounded exchange. Five credit tests, two budget tests and strict agent/content
Clippy pass; this is not yet an integrated network-contention or completed C04 proof.

Foreground native, named and cooperative-HTTPS downloads now use at most two concurrent provider
streams (`b172d11f`). The backpressured production-protocol test proves actual overlap: the fast
peer delivers three unique chunks while the other remains partway through its first response;
four unique cache inserts reconstruct five ordered chunks with one repeated hash. Missing or
failed chunks are reassigned only after their in-flight ownership is released. The idle-timeout
case permits one reconnect without resetting the original deadline or request budget. That test's
four variants, four existing provider tests, four stream-transfer tests and strict content/agent
Clippy pass. This is local stream evidence, not network timing, speedup, full C02 or a new VM pass.
The provider VM also has a bounded physical-packet overlap requirement. Twelve checker
and ten observer tests, plus a real disposable-veth timestamp test, pass locally; no live overlap
or throughput result is inferred from that observer preparation. The
[exact `b22a9153` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34193391288)
now passes that requirement: independent kernel-arrival timestamps for each provider's 64--960 KiB
bulk window overlap by 933,365,936 ns with zero timing errors. Native and named retrieval reconstruct
all 2,097,275 bytes / nine chunks from two providers; cooperative HTTPS completes from peers alone,
then from 1,048,699 peer bytes plus four exact 206 ranges / 1,048,576 origin bytes after withdrawal.
The ordinary cross-account publication chain also passes. All output hashes match, all 25 physical
and four control capture windows are complete/zero-drop, both providers stop and cleanup leaves
zero objects. Original ZIP SHA-256:
`6640485f36ec2c46cb19487b6dfda6f250467e2d2c492b8ffa753ff174580a60`;
byte-identical raw guest-state SHA-256:
`5b657d2aac41573b82609760e78f600d55d49d313eeb8552d4114789ea02a5da`.
Exact-source report and raw rebuild agree. This proves real overlap, not comparative speedup or
unique TCP goodput.

Replica capacity reclamation (`665fbfb4`) now runs before a new optional uptake attempt. It removes
only expired journaled chunks without live journal or explicit foreground references, preserves
unknown files and refuses mailbox-owned stores. Original expiry is never renewed; measured store
usage replaces guessed quota credit. Two core tests and one runtime filter pass, including a full
cache that rejects uptake, releases only the expired unshared chunk, then accepts real v3 uptake.
They advance an explicit library clock, not wall-clock or VM time. Strict content/agent/discovery
Clippy passes. This adds bounded local expiry reclamation, not retention repair, eviction of live
data, automatic boot service or full C04.

The new native `content fetch-name` command resolves an independently trusted publisher key
and exact name without a prior manifest file at the consumer. Providers explicitly enable
`serve --name-lookup`; original signatures are retained separately from optional replication,
and private-message manifests are excluded. One bounded round of at most 16 existing providers
supplies metadata and chunks through the normal protected route; no names enter the DHT.
The chosen revision is the highest valid one actually observed, not globally latest. Up to
64 durable cache-bound revision floors survive chunk eviction, expiry and restart; conflicting
same-revision envelopes and silent downgrades are refused, even when newer chunks are missing.
Two real library stream/cache tests, four prior provider tests and three replica-persistence
tests pass, together with strict content Clippy. Two agent observation/reopen tests and one
typed-wire test also pass, as does strict agent/local-control/CLI Clippy. Two real CLI-process/
Unixstream tests in capability-dropped namespaces and two parser checks pass: independent
key/name/minimum-revision/expiry, exact streaming, correlated completion and private no-clobber
output. Ten network-checker tests and targeted shell checks pass.
The additive network phase reopens both original 5+4 providers with name lookup, removes the
Client's old manifest copy, and requires fresh-cache retrieval into a separate user's `0600`
output plus the same full boundary captures and cleanup. The
[exact `d2f886c8` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186359414) now passes:
two independent providers supply all 2,097,275 bytes / nine chunks without a Client-side manifest,
reconstructing SHA-256 `add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
The separate user owns the `0600` output; the agent retains its `0700` cache and cannot read that
output. Exact no-clobber, both selected real WireGuard relay paths, provider/control captures and
the original native/HTTPS/ordinary-publication phases all pass. Cleanup leaves zero owned objects;
raw guest state is unchanged, SHA-256
`b6e480267d396e25110cd1609729a5312c1bf9371b7f5e57445e340cd3fb92ce`.
Artifact SHA-256: `44488197a0f8e5fe8c6f754f0a97182503f02e4713d4c67bf2316831ee97cac2`.
The exact-source checker and reconstruction from raw records pass locally. This is not yet
complete C06, generic website hosting, a mailbox or guaranteed offline availability.

The normal HTTPS command now also supports `--local-output`: the agent keeps its fresh origin
authorization alive while streaming verified chunks over the same authorized Unix connection,
then sends a correlated final receipt. The CLI verifies exact bytes/hash, original expiry and
receipt before atomically publishing a new user-owned `0600` file. It sends no user-output path,
creates no second cache or extra agent-output file, and retains no reusable HTTPS proof.
Existing `--output` and its wire operation remain unchanged. Two isolated real CLI-process tests,
three CLI argument tests, twelve origin-TLS/Range library tests, the new wire test and strict
four-crate Clippy pass. The existing complete/missing HTTPS topology cases now use separate
operator/service accounts, with exact output ownership, no-clobber and cleanup requirements;
their [exact `1024e6d2` network run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34184629816)
now passes. Both reconstruct 2,097,275 bytes / nine chunks into user 985's `0600` file while
agent 987 retains its `0700` cache. The complete case receives all bytes from two independent
providers and no origin body; the missing case receives 1,048,699 peer bytes plus 1,048,576
origin bytes in four exact ranges. The ordinary public publication sequence also passes.
All physical capture gates and cleanup pass; raw guest state is unchanged, SHA-256
`722dcae6ec43f24af7d3430cef084d89e455e4bdb5a8b822e029323c8ffb8320`.
Artifact SHA-256: `63f112d83b14cac188b07526146062eb9b5090eba74798bb062194cf7470a8e0`.
This is cooperative-origin CLI integration, not arbitrary browser HTTPS or a speed claim.

Explicit local `content import`/`content export` now bridge user-owned and service-owned private
message caches through the same authorized Unix control connection. Typed Ready/final receipts
surround the existing bounded chunk frames; the 256 KiB control-frame bound is unchanged.
By default only original signed private-message manifests and ciphertext cross that boundary.
Full-object hash/envelope validation is shared with normal opening; no recipient key/decryption is involved.
Import creates a new agent-owned cache, export a new user-owned cache, both `0700`; existing
destinations are refused and incomplete transfers are not success. Two agent stream tests,
one wire test, five existing message tests and strict agent/content/control Clippy pass. A real
CLI-process transfer in a disposable netns also passes. The
[exact `ec091bdd` VM run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34176555568)
now passes the different-UID extension: user 985, service 987, separate control group 986;
nine ciphertext chunks / 2,097,332 bytes reconstruct the expected 2,097,275-byte plaintext after
normal publish/import/export/open. Cache modes remain `0700`, plaintext `0600`, identities
unchanged and secrets unreadable to the other account. No service is implicitly activated.
Cleanup removes secrets/plaintext and all owned network objects; raw guest state before/after
is identical, SHA-256 `3f70c790a278cd5a80e4f6d2a0b04f1496e914c3d10d6851f71e006fc2e9bc41`.
Artifact SHA-256: `0f352df1445d02e3c8f9f4f176a08aeded77709ac81dd68c80470b1118537279`.
This is normal local sender/account integration plus the existing fixture-publisher network path,
not a complete normal sender network runtime, mailbox or C07. Exact CodeQL analysis passes;
Quality was cancelled by a newer head, not reported as passed.
The additive normal private-network harness is now committed as `f0936007` and its
[exact VM run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34182554210) **failed** its final
privacy evidence check. It preserves the earlier complementary-replica proof, then uses normal
publish-message/import/serve/fetch/export/open across separate operator/service accounts.
The new sender identity and plaintext input are removed before remote retrieval; the recipient
supplies its trusted key independently. Its local checks pass, including the positive Client-mount
access control before rejecting fixture-local cache shortcuts. The actual new transfer retrieves
2,097,332 ciphertext bytes and opens the exact 2,097,275-byte plaintext, but the Exit capture
records three outbound discovery attempts to the Client. Source tracing identifies empty
DNS-cache capability advertisements: a pure Client with no reusable proof is incorrectly offered
to an Exit's DNS peer lookup. The new availability-based publication correction is described
above; the boundary check is not weakened and this run remains failed. Cleanup leaves zero owned objects and raw
guest state unchanged, SHA-256 `c2864ace57362c8967429aa614de19b6c1660eeeae853ed12ce1ecc3c21e5a73`.
Artifact SHA-256: `fa73a1b1d77be63e177466e8b8ec03fad1dee96d30f4b4045a8aaad2196d83f6`.
A mailbox/full C07 or general combined-role unlinkability is not claimed.
The [corrected `1024e6d2` private-network run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34184627558)
now passes the complete normal sender publish/import/serve/protected fetch/export/open sequence
with sender secrets removed before retrieval. The exact 2,097,275-byte plaintext is recovered
from nine ciphertext chunks; account isolation, wrong-recipient/no-clobber checks and the
unchanged physical privacy gate pass, including zero Exit-to-Client discovery attempts.
Cleanup leaves zero owned objects and unchanged raw guest state, SHA-256
`caff570494b73a7d81ee4283d89c49782c6c1abdaa12118ff1c065b523839950`.
Artifact SHA-256: `3334c3d32813b41f7f4eb1475f674e10f6b5f67c781ee36c75f6b18d804b146d`.
The earlier failure remains a failure; this proves the corrected scoped path, not a mailbox,
automatic recipient discovery, durable offline availability or full C07.

The installed runtime ancestor now gives only search permission to the control group through a
non-inherited ACL, retaining the helper's required `0750` mode and private socket permissions.

The same account bridge now accepts an ordinary native publication only with explicit
`--public-content` (wire bool tag 5, false by default). It supports the existing 0--256 MiB bound,
with streamed full-object verification and finish-only empty transfers. Exact private-message
types retain their envelope/4-MiB check even with that flag. Public receipts cannot claim verified
ciphertext or HTTPS origin authentication. Two actual CLI-process tests, three agent stream tests,
one wire test and combined strict CLI/agent/control Clippy pass; they cover >4-MiB public files,
empty objects, default refusal and unchanged private behavior. The different-UID fixture
adds normal public publish/import/export/assemble; seven checker tests and shell checks pass.
Its [exact `49b6a7d1` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34177846462)
now passes nine public chunks / 2,097,275 bytes with the original expected hash, default refusal
before destination creation, isolated account ownership and unchanged identity. It also preserves
the private-message checks. All owned networks and temporary secrets/output are removed; raw
guest state is unchanged, SHA-256 `2caf3e00759c843289b12e4a01b4c6a11fe1e4ca009a01ad401b2afc5db24dc9`.
Artifact SHA-256: `2a535c5c2d07cb0164c713c4467016a17ee69113279dcc02807414c775ded6c4`.
No automatic serving, browser capture or HTTPS export is claimed.

The `content-provider` extension now composes those normal commands through the network:
a separate user identity signs an explicit file, imports it to one provider account and registers
it with normal Serve; the Client agent retrieves it through existing provider discovery and
protected MPTCP, then exports to the user for normal Assemble. The existing complementary 5+4
provider and cooperative HTTPS cases remain intact. A dedicated capture window binds the new
publication to its selected provider and both WireGuard relay paths; private fixture identity,
passphrase and input/output must be removed. Nine provider-checker tests, four replication tests
(including the large-report regression) and shell checks pass. Its
[exact `10f63244` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178615941)
now passes the ordinary-user network chain: all 2,097,275 bytes / nine chunks cross the protected
route and reconstruct with SHA-256
`add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
The new user's independent identity signs the publication; import/export retain the same manifest,
the user and service retain separate private ownership, and temporary secrets/input/output are
removed. The earlier two-provider native case and complete/missing cooperative HTTPS cases also
pass: the latter uses 1,048,699 peer bytes plus four exact origin ranges totaling 1,048,576 bytes.
Twelve Exit MPTCP flows complete. All twenty physical capture windows have stopped intake,
reconciled frame counts, zero drops and no forbidden packets. Cleanup removes all owned objects;
raw guest state is identical, SHA-256
`257bbc34127a6ed4d7876bdd5082343a609c5655e7a7e8644ce45b6c0a83b934`.
Artifact SHA-256: `d19a7501935ce31a3903d5ce24f61f0c86e9de9682834acf120a0241d13dcf45`.
The exact-source checker passes and reconstructs the report from the raw records. This proves
explicit normal native publication/retrieval across accounts and nodes, not a mailbox, arbitrary
browser HTTPS, general NAT reachability, speedup or complete C02/C06/C07.

The [corrected C03 run on `603cec9d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178099281)
now passes the complete bounded uptake/offline-provider/reopen/re-serving sequence. R4 retrieves
foreground P (524,609 bytes / three chunks), then opportunistically receives Q (262,267 bytes /
two chunks) using the one-chunk-credit exchange. Original R5's service and agent stop, with PID
zero and listener absent. R4 explicitly stops/reopens with only P's supplied manifest and restores
Q's independent replica registration. A fresh Client then retrieves Q over a new protected route,
matching SHA-256 `b5a1801633b0bb108ee611668a11f438f46f4d6d630f0bc394485a41ff2a401d`.
The uptake uses R0/R2 and final retrieval R0/R1; both selected WireGuard legs carry data. Actual
Exit and selected-Relay retirement completes before R4's `CLIENT_CLEANUP_COMPLETE`. Four Exit
MPTCP flows complete; all ten physical captures reconcile intake/frame counts, drain completely,
have zero drops and reject no packets. Final cleanup leaves zero owned objects and byte-identical
guest state, SHA-256 `8b8d47802f1a5ac13dc8601150f7537f453e9e1c2b6100a02238533e87426255`.
Artifact SHA-256: `4540417efb775503765c8a890af6c532e4b47a2d1dbb30651a041dbf64d16fcb`.
The exact-source checker and independent raw-report reconstruction both pass. This is the first
complete proof of that sequence, not full C03/C04, guaranteed retention/repair, automatic capacity
estimation or complete retirement-scope recovery. C05 DNS sharing remains incomplete and unverified.

Exact `10f63244` [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178579525)
fails in workspace tests: both `content_handoff_cli` process tests stop before execution because
`unshare` cannot write `/proc/self/uid_map` (`Operation not permitted`) on the CI runner.
Their passing local/VM evidence does not turn this run green; isolated CI execution still needs
correction, without a host-socket fallback. The
[CodeQL analysis workflow](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178576948)
passes, but the [separate PR alert gate](https://github.com/VOLPAROSSA/volparossa/runs/101912886127)
fails with 126 critical results. The unchanged count is not a new SARIF identity audit or a clean
security claim. No alert is dismissed and no failed run is relabelled.

The namespace runner correction in `41690c9` keeps real execution rather than skipping these
tests. It first tries disposable user/network/PID namespaces. Only an explicit CI-fixture opt-in
may use sudo for namespace creation when user mappings are denied; the exact test then runs as
the original user with capabilities removed. It never retries a failed test on the host network.
Both CLI tests and the new TCP collector pass locally through the corrected isolated runner.
The `0fa80d65` public DNS preflight now proves its explicit command-mode CI opt-in: Ubuntu denies
the user mapping, the fixed trampoline creates only disposable network/PID namespaces, and the
real collector runs as the original UID/GID 1001 with all capabilities cleared. This does not
retroactively pass the old handoff failures or a complete Quality run; `0fa80d65` Quality was
cancelled after the newer private-message harness was pushed.

The newer [exact `d2f886c8` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186330314)
fails in `ownership_journal::actor::tests::queue_capacity_reserves_shutdown_and_the_fence_linearizes_admission`:
initial `register_intent` returns `Ambiguous`, before the queue/gate assertions. The helper result
is 831 passed, one failed, two ignored; the short fixture setup deadline is under investigation,
not a proven cause. Three isolated local repeats pass, so the CI failure is not reproduced.
The fixture's two pre-gate durable setup operations now use its already established 2.5-second
I/O deadline, like the adjacent tests, instead of the 500-ms default intended for timeout tests.
The queue operations, reserved shutdown slot, fencing assertions and production deadlines are
unchanged. The changed queue test and adjacent timeout/fencing test pass; a new complete CI pass
is still required. The DNS actor actually runs and passes through the explicitly opted-in
disposable-namespace fallback, so this is not the old UID-mapping blocker. All three
[CodeQL analysis jobs](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186328279) pass,
but the [separate alert gate](https://github.com/VOLPAROSSA/volparossa/runs/101935381514) still
fails with 126 critical results. No alert is dismissed and no passing full-Quality claim is made.

The [exact `2459833a` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34187871366)
passes that helper fixture but fails the UDP shareable-availability test (18 pass, one fails).
Its assertion compares two exported expiry clones, each independently projected from the
monotone deadline to truncated wall-clock milliseconds. The test now checks against the actual
retained expiry and additionally requires both stored expiry and monotone deadline to remain
exactly unchanged. Resolver code, TTL authority and expiry limits are unchanged; the single
targeted test passes locally. All three [CodeQL analyses on this head](https://github.com/VOLPAROSSA/volparossa/actions/runs/34187869719)
pass, while the [separate alert gate](https://github.com/VOLPAROSSA/volparossa/runs/101939846881)
still reports 126 critical results. This is not a complete Quality pass or a new alert-identity audit.

The [exact `d1fd6d1f` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34191408128)
passes formatting and strict Clippy, then fails
`content_provider::tests::content_discovery_codec_roundtrip_and_bounds` with `Correlation`:
its maximum-size response fixture clones one provider identity sixteen times, violating the
response's required uniqueness (160 other discovery tests pass). The test-only correction uses
sixteen distinct identities and explicitly retains duplicate rejection; its targeted test and
strict content/agent/discovery Clippy pass, with production validation unchanged.
This is not the older formatting, namespace or DNS timestamp failure. The subsequent
[exact `b22a9153` Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34193378918)
now passes formatting, strict Clippy, workspace tests, namespace proofs and the final integration
harness. All [d1 CodeQL analyses](https://github.com/VOLPAROSSA/volparossa/actions/runs/34191404475)
complete, but the [separate PR alert gate](https://github.com/VOLPAROSSA/volparossa/runs/101950158074)
fails with 126 critical results. An equal count is not a fresh alert-identity audit or a clean gate.
All three `b22a9153` CodeQL analyses also pass, while its
[separate alert gate](https://github.com/VOLPAROSSA/volparossa/runs/101955945979) still fails with
126 critical results. The earlier failed workflows are not relabelled or bypassed.

### Preceding replica diagnostics and retirement integration

The [source-bound C03 run on `97e478a2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34175385789)
remains **failed**, but at a new boundary: final Client retrieval reaches provider discovery,
then reports `CONTENT_PROVIDER_TLS_FAILED` / `CONTENT_UNAVAILABLE` and Exit flow failure.
The old remote-WireGuard leak is absent: all ten physical captures are complete, drained,
zero-drop and contain no forbidden packets. Original R5 stops; R4's service stops/reopens and
restores Q's two chunks / 262,267 bytes / one replica publication (two total publications).
That run did not prove successful post-reopen retrieval. Global cleanup removes all owned objects;
guest root state is unchanged, SHA-256
`a6e726a2792fcdb336fac86949dbcc669a87b51dbd849262950c88f8d0075d18`.
Artifact SHA-256: `9e4363bd657127ce7438eb47a852f72385ce6b7970357a862d0b43325d0ffb40`.
The kernel evidence receives a SYN-ACK but not acknowledgements for the subsequent 261-byte
TLS payload. Source review does not justify changing TLS or widening ingress/firewall rules.
The [diagnostic run on `90c88a4b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34177039158)
gets beyond that failed final fetch: four Exit flows complete and the final-fetch failure hook
is not entered. R4 has a newly reopened listener, while its agent UID, reply route, RPF state
and firewall semantics stay unchanged. Relevant product code is unchanged from `97e478a2`, so
this is not an identified TLS fix; an intermittent cause remains unresolved. The run still fails:
the final report passed a large evidence object as one `jq --argjson` argument and hit Linux's
argument-size limit before copying the final receipts/hash/captures. Consequently those missing
proofs cannot support a C03 pass. Both diagnostic snapshots are complete; raw guest state is
unchanged, SHA-256 `9e7e8e95af3cd9a608b943c27757c32b8cab4a33efe36829aceffc374c879160`.
Retained artifact SHA-256: `63e8f36710f422fc7ec8c1050b19529cbcfbfdeb880b1225fa7b47b5cf75cdc8`.
Both replica and provider report writers now use file-backed JSON input and copy raw evidence
before serializing the report. One targeted regression exercises both real finalizers with
>160-KiB evidence, missing evidence and forced serialization failure (six cases, all pass).
Missing evidence still fails; a failed report no longer hides its raw observations. Shell checks
pass. The subsequent `603cec9d` result above verifies the corrected report and complete sequence;
neither earlier failure is relabelled. No traffic rule, timeout or packet gate is relaxed.

Exact `97e478a2` [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/34175365465)
and [CodeQL analyses](https://github.com/VOLPAROSSA/volparossa/actions/runs/34175362088) pass.
The separate PR alert gate reports 126 critical results. A bounded SARIF comparison against
`413cddca` (Rust analyses 1738252998 / 1738337615, same CodeQL 2.26.4 and category) finds exactly
nine added rule/fingerprint pairs and none removed: all nine are fixed test nonces reported by
`rust/hard-coded-cryptographic-value`, eight in `protocol/tests/route_retire.rs` and one under
`cfg(test)` in `discovery/src/route_retire.rs`. There is no added production location in that
delta; the pre-existing findings have not thereby been audited and the alert gate remains red.

That integration adds actual signed remote route retirement, rather than relaxing the
C03 packet boundary. An affine Client job retains its original session signer and exact selected
control/data relays before Finalize/ReservePath dispatch, including ambiguous rollback. Local
Destroy happens once; at most nine remote requests run in parallel with fresh per-target nonces.
Unconfirmed targets remain owned and coordinator/endpoint capacity is released only after all
Relay and independently verified nested Exit receipts bind the exact request. A stalled peer
does not prevent the other requests. The remote actors retain original authority across prepared
and running MPTCP/UDP/MPQUIC owners, request real shutdown/join/Destroy, keep failed owners for
retry and block late Prepare/Start for retiring contexts. A fieldless/generic reply is not success.

Two signed-message tests, one real two-hop codec test, six schema tests and a registry guard pass;
protocol/discovery strict Clippy passes. Three Client retirement tests cover ambiguous Finalize,
one unconfirmed peer and a stalled-first/live-other case. The real same-session signer/nonce/TTL
test and reservation Clippy pass. Two actor tests pass: actual three-node MemoryTransport with
independent signed Relay/Exit receipts, and a Unix helper-RPC proof of join-before-Destroy,
failure-retention and another context left untouched. Disabled runtime roles and expired original
grants do not block exact cleanup; wrong policy/session does. Strict agent Clippy also passes.
Normal daemon shutdown now keeps discovery alive until the bounded route-retirement attempt
finishes; a focused ordering test covers both confirmed and failed cleanup, with failure preserved
as `ShutdownCleanup`. The earlier `97e478a2` run observed the cleaned packet boundary but failed
at post-reopen TLS; the later `603cec9d` proof also completes retrieval. That later success does
not identify the earlier intermittent connection failure's cause.

Temporary functional limitation: each remote role retains at most 1,024 retirement scopes,
including completed ones; full maps reject new admission. Premature expiry-based deletion would
strand a later selected relay's confirmation. Safe capacity reclamation needs portable original
authority/terminal-scope evidence and remains unfinished, as does scope recovery after actor
restart. Missing state is never presented as proof that unknown helper resources disappeared.

The pushed replica-persistence checkpoint `413cddca` passes
[full Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/34173394726) and
[all three CodeQL analyses](https://github.com/VOLPAROSSA/volparossa/actions/runs/34173393113).
The separate PR alert gate still reports 117 critical alerts relative to its base, the same
aggregate count as `e592b610`; that is not a new full SARIF identity/delta audit or a green gate.

The [provider run on `e592b610`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34171708813)
is **successful**, including final evidence assembly. Normal native and complete-cache HTTPS
commands reconstruct 2,097,275 bytes from two independent authenticated provider nodes. A separate
missing-cache request combines 1,048,699 peer bytes with four exact 206 ranges totaling 1,048,576
origin bytes; every output has SHA-256
`add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
Eleven Exit MPTCP flows and six origin TLS 1.3 sessions complete. Provider withdrawal, physical
boundary/control captures and zero-owned-object cleanup pass; raw guest state is identical before
and after. Artifact SHA-256: `f645104c36fd58add5f146c63c20556e417c1752f07319902a314e0b22f74371`.
This is the explicit native/cooperative-origin retrieval proof; its report does not claim general
NAT reachability, arbitrary browser integration, speedup or full C02. Earlier failed runs below
remain historical failures, not current download blockers or retroactively changed reports.

The [same-source C03 run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34171709574)
completes v3 receiver-credit uptake: foreground P is 524,609 bytes; previously absent Q contributes
262,267 bytes / two chunks / one publication. With original R5 inactive, PID zero and listener
absent, a fresh independent Client fetches Q from R4 with the exact expected hash. All four Exit
MPTCP flows complete. The final privacy gate remains **failed**: exact fixture-private control
UDP/quoted port-unreachable packets need bounded classification, and R4's retired Client route
still receives WireGuard retries from its former remote relays. Local Destroy does not yet retire
their remote owners; they survive until expiry or global cleanup. This is an actual remote-route
lifecycle gap, not permission to allow those packets. All captures drain with zero drops and final
global cleanup leaves unchanged guest state. Artifact SHA-256:
`80b0f3f132cc02bda5f4abd751d1568392a106c3de92394e9db51906b0c7fee3`.
The next classifier only admits control UDP/ICMP on the exact configured xr3/xr5 address pairs,
requiring the outer ICMP tuple to reverse its valid, unfragmented UDP41000 quote. mDNS source
addresses are narrowed to the actual physical pair. Eleven capture tests pass; unexpected
WireGuard traffic remains forbidden while real remote retirement is implemented.

Explicit replica persistence is integrated locally. `content serve --reuse-replica-cache`
reopens the owned store, verifies a bounded cache-ID-bound journal and original signed manifests,
and registers live chunks before starting a listener. Successive uptake merges old chunk sets
without renewing expiry or turning a storage peer into a publisher. Missing journals restore no
registrations; corrupt/foreign/busy stores or missing live chunks fail. Expired entries are not
served, but their bytes are not automatically deleted. Three real library persistence tests,
two agent tests, one CLI test, one typed wire test and combined strict content/agent/CLI/control
Clippy pass. The C03 fixture explicitly stops/reopens R4's service after R5 is offline, without
supplying Q's manifest to R4, then requires Q to be retrieved from that restored registration.
Three evidence-checker tests and shell syntax pass; `603cec9d` now confirms both restored
registration and subsequent retrieval, following the earlier failures recorded above. At that
checkpoint, automatic boot service, retention repair, expiry reclamation and full C03/C04 remain
incomplete; the later bounded local reclamation in `665fbfb4` is recorded above, not attributed
to this older VM.

Exact `e592b610` [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/34171679274) and
[CodeQL analysis](https://github.com/VOLPAROSSA/volparossa/actions/runs/34171677187) pass. The separate
PR CodeQL alert gate remains failed with 117 base-relative alerts; it is not a green security claim.

## Earlier source-scoped content checkpoints

The [content KVM run on `f0a906ca`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34146922945)
passes through existing genuine MPTCP/TLS and both WireGuard legs. Bounded owned caches rebuild
2,097,275 bytes / nine signed chunks after removing the publisher directory/key. The first
provider supplies five pieces; the consumer restarts, reopens its cache and downloads only four
missing pieces from the second. Exact output SHA-256:
`add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.
Both provider processes observe the Exit address, and both selected relay paths carry real
WireGuard datagrams. All ten boundary privacy captures have stopped intake, reconciled packet
counts, zero drops and no direct/boundary-violating packets. Four separate application-capture
summaries do not contain drop counters; they are not included in that ten-window claim.
Cleanup leaves zero owned objects and unchanged guest state. Retained artifact SHA-256:
`760c90457c835c6ca4392168f06c9f701f98b092a07af778127aa6e35c826fbd`.
Together with the existing integrity/quota/missing-part tests, this establishes C01. Two replica
processes at one policy-authorized destination do not establish independent provider nodes,
discovery, automatic redistribution, initial distributed publishing/retention, HTTPS or DNS.

The normal `volparossa` executable now exposes offline `content publish` / `content assemble`.
Publication unlocks the existing encrypted node identity without creating or exporting another
permanent private key. Reconstruction requires an independently trusted publisher key and
1--16 explicitly selected owned caches. Two focused CLI tests, strict CLI Clippy and a build
pass. Separate CLI invocations reconstruct an identical 18,742-byte file, reuse an owned cache,
and reject a wrong publisher, missing chunks and output overwrites. Tests also reconstruct
from two partial stores after removing the original input. These are real local commands,
not automatic network publication/discovery or a newly verified installed Debian package.

Normal private-message commands now extend that executable: `content recipient-key`,
`content publish-message` and `content open-message`. The recipient key is derived in memory
with the pinned RFC 9180 DHKEM implementation and an exclusive versioned domain from the existing
encrypted identity, not written as another plaintext secret. Seven targeted content CLI tests
pass, including identity reload, two partial ciphertext caches, wrong sender/recipient rejection,
atomic 0600 plaintext output, no overwrite, unchanged identity and passphrase-change continuity.
A separate-process CLI smoke also passes: the actual executable publishes and opens a binary
message across fresh processes, rejects a wrong recipient and output overwrite, and leaves both
encrypted identities byte-identical. Strict CLI/content Clippy passes, including the new test.
Identity rotation changes the recipient key and is explicitly warned about; there is no forward
secrecy, profile-specific key separation, mailbox, key discovery or C07 completion claim.

The `content-message` network harness now uses normal `init`, `recipient-key` and `open-message`
with two disposable encrypted IdentityStore files and a private CSPRNG passphrase. The provider
UID must be unable to read either identity or the passphrase. The checker requires actual wrong-
recipient rejection, new 0600 plaintext output, no overwrite, unchanged encrypted identities
and exact secret-file cleanup. Five checker/cleanup tests and a real separate-process CLI/fixture
compatibility test pass; shell syntax, the changed hook's ShellCheck and plan preview also pass.
The [exact `4c4c8954` network rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170523962)
now passes: nine ciphertext chunks (five plus four) reconstruct the exact 2,097,275-byte message
through normal recipient CLI commands. Wrong-recipient/no-clobber/identity-preservation checks
pass; both MPTCP flows and both WireGuard relay paths carry data. Ten boundary captures drain
with zero drops or unexpected packets. Secret fixtures are removed, cleanup leaves zero owned
objects, and raw before/after guest state is identical. Artifact SHA-256:
`19e8b4587c5b44f52112b135c3f864d47de2e64e0b8fdca7a3d4ea924d26898e`.
The publisher is still the existing encrypted-message fixture; normal publisher CLI networking,
key discovery, mailbox and full C07 are not claimed.

The new explicit `content serve` / `content fetch` / `content stop` runtime now compiles with
strict agent, CLI and local-control Clippy. Serving registers up to 64 exact verified manifests
from owned caches and signs a five-minute service offer with the existing node identity.
Generic provider lookup goes through a current authenticated control Relay; neither object IDs
nor URLs enter Kademlia. Fetch verifies signed offers, excludes the carrying route's Exit/Relays,
and uses the existing policy-authorized MPTCP/TLS flow for each provider, never direct TCP.
Five focused discovery-wire tests, four agent discovery tests, four provider/registry tests,
three CLI tests and two typed local-control tests pass. The first
[independent-provider KVM attempt on `aa634ce1`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34155097741)
**failed before retrieval**: both provider services registered, but the control Relay started its
query without receiving verified offers or completing discovery; the consumer returned
`CONTENT_UNAVAILABLE`. The missing broker-to-provider control connectivity in the disposable
topology is being corrected. Cleanup completed with no remaining owned objects and unchanged
host state. [Quality on that same source](https://github.com/VOLPAROSSA/volparossa/actions/runs/34155036080)
passed, but does not turn the failed datapath into a pass. There is still no live independent-node
provider-discovery/fetch proof or C02/C06 completion. No default listener, automatic browser
capture, replication/retention or speedup is implied.

The next candidate adds the missing two disposable broker/provider control links, restricted
to UDP 41000 with exact advertised-address routes and separate fully drained captures. It
also separates the relay's 10-second collection budget from the unchanged 15-second reply
deadline, so a slow DHT walk need not erase already verified offers. This timeout correction
does not establish the cause of the earlier zero-offer run or claim complete DHT visibility.

The [combined provider/HTTPS attempt on `3d8e4827`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34157126112)
also failed in native fetch, before either HTTPS case ran. Its actual kernel route receipts
confirm both new control links, but the Client capture contains no control-Relay request and
neither broker link carries frames. This is not evidence of a DHT lookup or HTTPS success.
Cleanup again completed with zero owned objects and unchanged guest-root state; the artifact
SHA-256 is `f62cd4955a087db1f39ac9019d4d4cb75afaef49bc227324a807991f2cde4d84`.
Fixed, bounded diagnostic codes now distinguish route/control availability, actor delivery,
current authority/connection checks and RPC dispatch, without logging peer IDs or resources.
The [diagnostic run on `e9b5274b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34158695243)
then records `CONTENT_FETCH_ROUTE_READY`, `CONTENT_DISCOVERY_COMMAND_RECEIVED` and
`CONTENT_DISCOVERY_CONTROL_CONNECTION_INVALID`. The route/control capability passed; the
current connection-provenance check rejected the request before dispatch. The underlying
registry condition is under investigation, not attributed to DHT/HTTPS or bypassed. That run
again cleaned up all owned objects with unchanged guest state; artifact SHA-256:
`d93c6f36684a63e237d8e0a30b0936cfe5006802f4dd79cf0f67ac82e81cc997`.

The next candidate fixes the content-specific dispatch contract: it observes the existing
request-response behaviour's actual `NotifyHandler::One` choice, validates that exact current
authenticated direct connection before forwarding it, and binds the reply to the same ID.
Multiple authenticated sibling connections are not themselves an error; there is no arbitrary
registry-first choice, autodial, sibling retargeting or change to native-prefix witnesses.
Fixed codes distinguish absent, poisoned, non-direct and multiple-connection registry states.
Nine focused discovery tests (including a two-connection Noise/Yamux MemoryTransport roundtrip)
and five agent discovery tests pass. These establish the bounded dispatch mechanism, not the
cause among the old undifferentiated registry states or a passing independent-node KVM result.

The [exact `fdcb64d3` run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34160670839)
now proves that fix on the live topology: `CONNECTION_MULTIPLE` proceeds to actual dispatch,
two provider offers are verified, and discovery completes. Retrieval still fails afterward:
the native selector is written without application TLS, while the unchanged Exit policy
requires a real ClientHello matching the authorized provider hostname before opening egress.
Both flows are rejected before any provider TCP connection. A provider-authenticated TLS layer
is being integrated; neither a policy bypass nor a completed download is claimed. All five
boundary captures and both broker-link captures drain completely with zero drops or violations;
cleanup leaves zero objects and identical guest state. Artifact SHA-256:
`e1d62ea06f4b0cb3364482d24f40e6f02ac9dff4e8b79dc115b5949c260df896`.
Exact-source Quality passes strict Clippy but fails one discovery source-surface test: its
old one-enum assertion omitted the new fieldless diagnostic enum. The assertion is updated to
allow exactly those two named enums; the registry/authority restrictions remain unchanged.

The provider runtime now adds actual TLS 1.3 inside the protected flow, reusing the pinned
libp2p certificate identity proof. The server identity must match the verified service offer;
the exact advertised SNI and content ALPN are required. Each consumer session uses a fresh
temporary TLS identity, never its permanent Client key. This authenticates only the provider,
not a publisher or HTTPS origin. Foreground native/HTTPS peer pulls and replica uptake share
the same connector. Three focused tests pass: real independently authorized chunk transfer,
wrong-provider/SNI rejection, and nested TLS through the actual bidirectional proxy with clean
half-closes and different ephemeral Client identities. Provider sockets now use the existing
contribution priority; actual owner-contention behavior still needs its own live proof.
The eleven existing HTTPS tests, the corrected registry test, strict agent/content Clippy and
formatter checks also pass. HTTPS closes only after the existing exact-body/origin checks and
does not confuse a complete HTTP body with clean carrying-transport EOF; the agent separately
requires outer TLS completion. The independent-node KVM rerun is still pending.

The [next run on `a20efb71`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34163225687)
does complete all three real downloads: native and origin-authenticated complete-cache retrieval
each receive 2,097,275 bytes from two independent nodes; the missing-cache case combines
1,048,699 peer bytes with four exact HTTPS ranges totaling 1,048,576 bytes. All three outputs have
SHA-256 `add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`, and all eleven
protected Exit flows complete normally. The final HTTPS evidence check nevertheless fails:
it incorrectly expects the Exit's provider-facing address `46.162.3.1`, rather than the
destination-facing `xd` address `47.163.4.1` configured by the unchanged topology. The checker
now requires that exact destination-facing address and explicitly rejects the other one.
Its two tests and five combined-provider checker tests pass. Re-evaluation of the unchanged
raw HTTPS records with the corrected checker passes both cases; all eighteen physical/control
captures drain completely with zero drops/violations. Cleanup leaves zero owned objects and
byte-identical guest state. Artifact SHA-256:
`be976de3e8d44098ac799518624b89ad9a4a5233e5ae4396d5969005e7d1b7ce`.
The historical run remains **failed**, and its final native-provider stop/status steps were not
reached; no successful final report is invented from the re-evaluation. [Quality on exactly
`a20efb71`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34163214885) passes in full.

On [`472b6e7a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34164938658), native and
complete-cache HTTPS again use both providers successfully. The subsequent missing-cache
lookup verifies one offer at the control Relay but returns no usable provider: HTTPS therefore
reconstructs the correct object entirely from the origin instead of the expected four missing
ranges. The origin fixture waits for the remaining expected range requests and times out.
This is a distinct integration defect, not the corrected Exit-address check. Route identity,
expiry and offer lifetime do not explain it. All eighteen captures drain with zero drops or
violations; cleanup leaves zero owned objects and unchanged guest state, but the final service
stop/report is not reached. Artifact SHA-256:
`908c0a0ca75c110f4b9661ada2762bf8b62ed9a6e59f6ce22f310210d1ae862c`.
[Quality on this source](https://github.com/VOLPAROSSA/volparossa/actions/runs/34164918500)
passes in full. Fixed, detail-free lookup-completion diagnostics are being added to distinguish
the remaining offer-loss paths without changing timeouts, retries or authority requirements.

The first C03 redistribution library and normal agent hooks are now integrated locally. Five
duplex tests pass: uptake then re-serving, non-evicting quota, exclusions/duplicates, signed
expiry/hop bounds, corrupt input and timeout. Existing v1 provider tests remain 4/4 passing.
The job reuses a provider that supplied verified foreground bytes, opens a separate existing
policy-authorized MPTCP/TLS stream, and admits at most four chunks / 1 MiB of total protocol
traffic into a distinct private cache. Storage-only replica signatures do not become publisher
or HTTPS trust. Fresh read-only link samples gate starting; foreground content requests and
service stop cancel uptake. A full-budget cooldown bounds the declared average traffic budget,
not instantaneous owner/radio contention. Agent/UAPI compilation and strict Clippy pass; three
focused cache/owner-generation/idle-accounting tests and the UAPI counter test pass. Independent-node C03 uptake/re-serving,
durable registration/retention and complete C04 owner isolation remain unproven and unchecked.
See the [bounded redistribution scope](CONTENT_NETWORK_PROPOSAL.md#bounded-post-download-redistribution).

The next local owner-priority slice uses explicit replication v3, with one receiver credit per
chunk and a fresh configured-interface quiet sample before each credit. Busy ends the exchange
with its independently verified partial uptake; the original expiry, byte budget, hop ceiling
and deadlines are unchanged. The provider snapshots bounded registration metadata and releases
cache handles before waiting for credit or writing a chunk, allowing a foreground retrieval to
proceed. Four real duplex tests pass: no unsolicited next chunk, a concurrent foreground pull,
busy-stop preserving verified partial data, exact credit/framing byte accounting, fixed deadlines
and refusal of a v2 response. Five existing v2 tests, three agent budget/lifecycle tests and
strict content/agent Clippy also pass.
This is not a live all-interface contention/no-slowdown proof: one credited chunk may overlap
new owner demand, only configured interfaces are sampled, and full C04 remains unchecked.
The network attempts on `4c4c8954` predate this v3 slice and cannot establish its live behavior.

The separate `content-replication` KVM scenario now drives normal agents through foreground P,
uptake of previously absent Q, original-provider agent shutdown, and a new consumer's protected
Q retrieval from the replica. Five-role physical captures cover both phases and all fixture
interfaces, with actual object hashes, fresh-cache isolation and unchanged-host cleanup gates.
The two evidence-checker tests, five capture tests, thirteen existing benchmark tests and narrow
shell/runner checks pass. Its [first live run on `a20efb71`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34163227425)
fails before the first download: the fixture leaves only two reachable relays, while normal
preselection requires a separate control relay plus two data relays. Both original publications
register, but the replica's route remains unavailable with `PRESELECTION_SAMPLE_INVALID_SNAPSHOT`.
The fixture needs a third control-capable relay; the product's route/privacy requirements are
not lowered. Cleanup completes with zero owned objects and unchanged guest state. Artifact
SHA-256: `aa35f10306adbb4d275475c0331ffeff386faf4630162d970b8e91b5b89005ea`.
No uptake, re-serving or C03 completion is established by that failed run.

The [three-candidate rerun on `472b6e7a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34164939638)
now establishes the route and fetches P (524,609 bytes / three chunks) from the independent
original provider. The replica service then starts with an empty replication cache, but the
second foreground P request encounters the same verified-offer loss and fails before Q uptake.
All five capture windows drain with zero drops. The Exit window nevertheless contains two
unclassified forbidden packets (no direct-client/Exit or direct-provider packets); that is not
a privacy pass and is being diagnosed separately without broadening allowed traffic.
Cleanup leaves zero owned objects and unchanged guest state. Artifact SHA-256:
`2ee3503a3875b7516ad62a1d9f5a65ed6ae57857ea11151e2c56cfcac9bf528a`.

The [diagnostic run on `9f0afbb6`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34166433232)
fails earlier, during the first P fetch. Control Relay R2 completes its DHT lookup with a valid
reply authority but an empty offer collection; unlike the previous run, no verified-offer event
precedes that result. The actor already waits for in-flight offer requests after DHT completion,
so no premature-join or expired-authority fix is justified by these events. More specific bounded
request-outcome diagnostics and a local real-Kademlia reproduction are being developed. This
run never reaches the uptake captures, so it does not identify or clear the two earlier forbidden
packets. Cleanup is complete with unchanged guest state. Artifact SHA-256:
`b95524d9b54cdcc2dec387859075c1f4010817ccd83b3a268e4bef2e42297e3a`.
[Quality on the same source](https://github.com/VOLPAROSSA/volparossa/actions/runs/34166413926)
passes in full; that does not make the failed functional scenario a pass.

The [request-outcome run on `cd291c50`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34167932193)
now distinguishes the first-fetch failure: control Relay R1 finds the provider and receives an
empty service response four milliseconds after dispatch. R5 registered its offer about 40 seconds
earlier. This is not a dial failure or a signed-offer rejection. Cleanup completes with unchanged
guest state; uptake/captures remain unreached. Artifact SHA-256:
`cfc42b5edc73a1a50dfef9c932893019ba63fdf3ca3fc3200a64942b1c4a5793`.

The following ownership correction removes content withdrawal from native Relay/Exit advertisement
withdrawal. The explicit content listener owns its own registration: stop, policy replacement,
shutdown and the earlier of offer/policy expiry still invalidate it. A real actor regression
fails with the old coupling and passes with the correction; all eight discovery-content tests
pass, including earlier policy expiry, unchanged deadlines, explicit stop and policy replacement.
The independent-node runtime must still be rerun; this does not retroactively pass the earlier
failed reports or clear their packet findings. Separately, the real Kad/RPC characterization
confirms that an unadmitted provider-record address alone cannot be used for redial; the product
already has authenticated Identify address admission, and no speculative addressbook change was made.

The next exact-source runs on `7daa72a6` expose a second, reproducible lifecycle defect.
The [provider run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34169522477) verifies both
offers before the unchanged 30-second policy reload invalidates the collection. The
[redistribution run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34169524017) loses its
original provider registration at that same maintenance boundary and fails before warmup.
Both cleanups leave zero owned objects and byte-identical host state; the earlier two forbidden
Exit packets remain unresolved because no new uptake capture was reached. The narrow correction
now preserves content only when both policies are active and their canonical hashes match;
all original offer/query deadlines remain unchanged. An actual ApplyPolicy regression fails
without the correction and passes with it, including real policy replacement invalidation.
All nine discovery-content tests and strict agent Clippy pass. No retries, longer timeouts,
weaker authority checks or completed C02/C03 claim are introduced; live verification is pending.

The [redistribution run on `4c4c8954`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170522891)
now completes the actual four-flow sequence. R4 fetches foreground P (524,609 bytes), then after
another P fetch takes up previously absent Q (262,267 bytes / two chunks / one publication).
R5's original agent is stopped, PID zero and its listener absent, before a fresh Client cache
fetches Q from R4 with exact SHA-256
`b5a1801633b0bb108ee611668a11f438f46f4d6d630f0bc394485a41ff2a401d`.
The four Exit MPTCP flows complete, and cleanup leaves zero owned objects with byte-identical
guest state. The run nevertheless remains **failed**: full physical captures contain packets
the classifier rejects. WireGuard padding/MTU, control/dataplane ordering and mDNS source-port
assumptions are being corrected; additional ICMP observations remain unresolved rather than
being allowed speculatively. This establishes actual uptake/re-serving, not a successful final
privacy report or full C03/C04. It predates the new receiver-credit protocol above.

The [provider run on the same `4c4c8954` source](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170521790)
also completes native, complete-cache HTTPS and missing-cache HTTPS, with the exact 2,097,275-byte
object hash in every case. The latter combines 1,048,699 verified peer bytes with four exact
206 ranges totaling 1,048,576 origin bytes. Eleven Exit MPTCP flows complete and both provider
services stop. Only final report assembly fails: its object-only reader rejects the actual
one-element kernel-route JSON arrays. The corrected bounded array reader preserves all exact
peer/address/gateway/interface/capture checks; seven checker tests and re-evaluation of the
unchanged raw evidence pass. Cleanup is complete with unchanged guest state. The historical
workflow remains **failed**, not retroactively repaired. Exact-source
[Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170509341) and
[CodeQL analysis](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170507762) pass; the separate
CodeQL PR gate still reports 117 alerts relative to its older base and is not described as green.

The next capture checker corrects three source-established assumptions: Linux's observed
1420-byte WireGuard MTU permits a 1452-byte padded data message; normal authenticated-control
traffic on the fixture's UDP 41000 is not a direct Exit dataplane; and the pinned mDNS sender
uses an ephemeral source port toward the same bounded local multicast destination. Direct
dataplane traffic, oversized/other malformed data and all unexplained ICMP remain rejected.
Fixed per-interface ICMP/quoted-UDP categories will distinguish the remaining observations
without recording packet bodies or tuples. Nine capture tests and three replication-evidence
tests pass. The old capture summaries cannot be reclassified into new observed packet evidence;
a fresh source-bound run is still required.

Native and HTTPS fetch now support explicit `--reuse-cache` across CLI, typed local control and
the agent. Default creation still rejects existing directories; reuse opens only a validated
owned store and output remains no-clobber. Already verified chunks skip requests, while HTTPS
obtains fresh origin authorization and preserves its original authenticated expiry. Six targeted
tests and strict CLI/local-control/agent/content Clippy pass. These include a real interrupted TLS
body followed by close/reopen, fresh metadata authentication and exactly the remaining Range;
native partial retrieval resumes similarly. A partial-progress API records verified received
payload even when eviction leaves zero net cache growth, without counting cache hits as traffic.
This local resumption proof is separate from the pending full independent-node integration run.

The next slice encrypts native messages to an independently authenticated recipient key before
chunking, using the existing RFC 9180 HPKE dependency/profile. Five focused message tests and
strict content Clippy pass. A separate-process disposable-loopback proof transfers 2,097,332
ciphertext bytes / nine chunks from two replicas after publisher removal and reconstructs the
original 2,097,275-byte plaintext only for the recipient; a wrong recipient is rejected. Its
explicit temporary fixture key and plaintext file are removed afterward. The library persists
neither and returns plaintext in zeroizing memory. The
[`content-message` KVM run on `b1082645`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34149009080)
now passes that encrypted offline-retrieval sequence over real protected MPTCP/TLS and both
WireGuard legs. The recipient's UID-985 0600 key in its 0700 directory is unreadable to UID-987
providers; key, plaintext and private directory are removed. Ten boundary captures are fully
drained with zero drops/violations; four separate application captures make no drop-counter
claim. Cleanup leaves zero owned objects and byte-identical guest state. Retained artifact:
`873a5248f679e03e4a702b6fbedeafbf13f06d75ac67e9d48fb57c011754457a`.
This proves the configured encrypted-transfer substep, not a complete mailbox, recipient-key
discovery/storage, forward secrecy after key compromise, anonymous metadata or complete C07.

The cooperative-origin HTTPS slice now uses real TLS 1.3 hostname/CA verification to obtain a
bounded canonical resource descriptor, then supplies its independently origin-authorized native
manifest to the same chunk-transfer API. Only anonymous GET/200 identity-encoded binary content
with explicit public freshness is admitted. HTTP Date/max-age, descriptor/signed expiry and
monotonic elapsed time bound reuse. Seven focused real-TLS tests and strict content Clippy pass.
A separate-process disposable-loopback proof fetches just 777 metadata payload bytes from the
origin and reconstructs 2,097,275 bytes from two partial caches, with zero origin body bytes.
In a separate empty-cache case, one partial replica supplies 1,048,699 bytes; missing chunks
trigger a complete 2,097,275-byte origin response checked against the same manifest. Changed
origin bytes fail the focused test instead of being mixed into a successful object. This is
full-body fallback, not optimized Range retrieval or a speed comparison. The
[`content-https` protected-route run on `2de8209f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34150683819)
passes: both independent consumers reconstruct the exact object, origin metadata/body use real
TLS 1.3, all six application streams traverse protected MPTCP/TLS and both WireGuard legs,
and all origin/provider connections observe the Exit source address. Ten boundary captures
are complete with zero drops/violations; four application summaries make no drop-counter claim.
Cleanup leaves zero owned objects and unchanged guest state. Retained artifact SHA-256:
`27059f12ecadc952ae7d86d4e0fd0ec32fa01345600d776b12a377c0533d96c8`.
The next implemented API/example requests only the first contiguous missing chunk range over
each verified origin TLS stream. Eleven focused TLS tests, strict content Clippy and a build
pass. Its separate-process disposable-loopback proof reconstructs the identical object using
1,048,699 peer bytes plus four exact 206 responses totaling **1,048,576 origin body bytes**.
The complete-cache case still receives no origin body. Range offsets/total/length and every
chunk are checked against the unchanged origin authority; an ignored Range/200 response is
fully verified and its full byte cost reported. The extended
[`content-https` run on `6cf2394b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34151753705)
now passes the same exact four-range retrieval with nine protected app flows, real TLS 1.3,
both WireGuard legs, ten complete zero-drop/zero-violation boundary captures and zero remaining
owned objects with unchanged guest state. Its artifact SHA-256 is
`729820100b4a4035eb7e006fe0b5801637d74912a11151f90ec2031d64400d79`.
[Quality on that exact source](https://github.com/VOLPAROSSA/volparossa/actions/runs/34151736141)
also passes. This reduces origin payload in the fixture, not proof of a throughput gain.
Publisher cooperation is required. No browser integration,
generic existing-site compatibility, TLSNotary, distributed discovery or C08 completion is claimed.

The next local checkpoint composes this API in the normal **`content fetch-https`** command and
typed agent operation 24. A canonical HTTPS URL and exact same-origin metadata path select an
explicit public resource; the agent obtains the descriptor through real hostname/CA-verified
TLS 1.3 over its policy-authorized MPTCP stream before asking the carrying route's authenticated
control Relay for generic provider offers. Cached chunks are verified against that in-memory
origin authority; missing chunks use authenticated origin ranges. An ignored Range/200 response
is still fully verified, and actual overlapping transfer bytes are counted rather than hidden.
The receipt reports `origin_authenticated`, `peer_bytes`, `origin_body_bytes` and
`origin_range_requests`. New cache/output paths are explicit; no object URL is added to DHT or
background browsing logs. Debian system roots are used by default; optional `--ca-file` supplies
at most 128 KiB of explicit public certificate PEM for this request only, without installation,
interception CA, private-key loading or TLS-verification bypass.

Three focused agent CA/request tests, two CLI parsing/file-bound tests and two typed local-control
tests pass, together with strict agent/CLI/local-control Clippy. Receipt checks retain the
256-MiB object/peer budget, at most 1,024 origin ranges, and a 512-MiB origin-byte ceiling for
disjoint ranges followed by one fully verified 200 body. These are local integration checks,
not a normal-CLI network success: its exact KVM proof is still pending, the failed provider run
above remains failed, and **C02/C06/C08 stay incomplete**. The earlier `2de8209f` and `6cf2394b`
HTTPS passes belong to their executable-fixture builds and do not certify this newer command.
The combined provider scenario now invokes the normal CLI against the exact same signed
publication: two-provider HTTPS retrieval, then a fresh-cache request after withdrawing one
provider, requiring the four missing origin ranges. Its source-bound evidence requires actual
peer/origin byte accounting, TLS 1.3, the same protected MPTCP route and complete cleanup.
Both focused checker groups and the non-network KVM contract pass; the real VM result remains
pending and is not inferred from those checks.
README and the relevant architecture/protocol/privacy/testing summaries are updated together;
detailed changing results remain centralized here and in the content proposal.

The complete cooperative `download-sharing` run on unchanged `efc35ac9` is now green.
Mixed-link now has one scoped passing gain comparison, following the failed attempt below.
Native `76f907fc` preserves all FIFO checks while replacing bytewise zero scanning with
aligned-safe full-range word reduction. The
[exact-source mixed-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34146021889)
completes both hash-matching 32-MiB responses: WAN-only 6.209 Mbps versus LAN+WAN 6.081 Mbps,
a **0.979x** ratio below the unchanged >1.25x gate. Steady Exit Send/Receive dispatch means fall
from 567.6/308.5 us to 208.2/97.6 us, but only about 7.25% of aggregate response WireGuard bytes
use LAN. Baseline and aggregate also select different WAN relays; this is not an isolated A/B
control. Eight native captures are complete without drops or boundary violations, cleanup is
complete and guest state unchanged. Artifact SHA-256:
`59e6fc94f7f00875d4c2ff9c96c323f45853c506cd262d59611ee65e043f1ca0`.
The next candidate adds a default-off Exit EDT diagnostic: at most 64 sparse metric-only samples
in seconds 10--20 after first non-startup application scheduling, not after an HTTP response.
Pinned callback tests and focused ASan/UBSan pass; no scheduler selection, congestion control
or traffic policy changes. The
[`b1082645` mixed-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34149010127)
passes: WAN-only 32 MiB in 41.221 s (6.512 Mbps), LAN+WAN in 32.841 s (8.174 Mbps), ratio
**1.25517x**, only 0.414% above the unchanged 1.25x gate. Both cases use WAN Relay0, though
their contexts are warm/fresh. Matching endpoint hashes, warm-context failover, eight complete
zero-drop privacy captures, zero remaining objects and unchanged guest state pass. Artifact:
`09af5558df8225a7bf4b50404234757ad2555993e4f5d2cae0ef0ccf712800dc`.
The fresh connection's 64 sparse response-window samples select LAN 50 times, consistent with
78.54% of received response WireGuard bytes using LAN; all follow the lowest existing EDT cost.
The prior attempt had different path ordering/baseline relay and execution costs. This is one
passing configured topology, not repeatable/general gain or evidence that diagnostics repaired
the scheduler. Native tuning is paused for this functional checkpoint.

[Quality on `b1082645`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34149000752) passes
workspace tests and strict Clippy. It includes `9e2cab8`'s guaranteed-diverse sampler success
fixture and deterministic rejection coverage, without changing production selection. It does
cover the encrypted-message/diagnostic slice, but not the subsequent HTTPS/CLI work. Download evidence below does not
establish automatic Internet-capacity detection or general Wi-Fi airtime fairness.

## Current live integration checkpoint

The [full v1 run on `482e33d0`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34047766913)
**passes all A01--A15 on one unchanged build**, and
[Quality on that exact revision](https://github.com/VOLPAROSSA/volparossa/actions/runs/34047735082)
passes workspace tests and strict Clippy. The retained artifact digest is
`20c6c0eede3d927a7b911ad6182b5098276d67627d8d6d91e6b886197c0546d1`.
Independent inspection confirms all ten raw native/MPTCP privacy capture windows:
zero socket drops, no truncation, stopped intake and reconciled per-interface packet
counts. A03 measures 2.022x real MPTCP aggregation. A07 completes its 32-MiB response
in 65.662 seconds while retaining the same fresh context across Relay2 removal and
surviving over Relay0. All 25 forced crashes and helper restart recovery pass; remaining
objects, namespace references and descriptors are zero, and guest state is unchanged.
This meets the original v1 live acceptance sequence, not every subsequent extension
or release-readiness requirement.

The [same-build mixed-link attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34047765944)
passes A06's two-path 8-MiB response, but its separate WAN-only baseline times out after
removing the LAN path from the warm route. The first retained Client failure is
`INGRESS_MPQUIC_DATAGRAM_REJECTED`, followed by rejected non-initial QUIC traffic;
no completed 32-MiB baseline or new gain ratio exists. Cleanup completes with unchanged
guest state. The cause is still being investigated; the successful fresh-route A07
above does not prove this distinct warm-context case or useful LAN+WAN speedup.

Owner-priority cooperative downloads now have a
[complete live pass on `efc35ac9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34142685975)
through signed adjacent budgets, the route actor, helper-owned sender queues and same-hook
receive accounting. This is one manually configured IPv4 bottleneck, not automatic capacity
detection, arbitrary ISP guarantees or Wi-Fi airtime control. Physical-radio testing remains
explicitly deferred until hardware is available; simulated Linux Wi-Fi evidence below is not
substituted for physical-device testing.

The retained download artifact SHA-256 is
`e96e533711558ee5f05cf28e5b65d9ae129fa1fa0be5508100d67b71f410eb4b`.
Application-goodput windows show contributed download at 2.273 Mbps while idle, zero while
the owner's traffic receives 11.636 Mbps (owner-only baseline 11.626 Mbps), and 2.339 Mbps
after owner traffic stops. Sender-queue counters independently go to zero during owner demand.
Pausing budget refresh produces a bounded 2,564,059-byte tail; the post-grace window admits no
contribution. The exact protected context and both WireGuard legs are retained. Captures are
complete with zero drops, both receiver-accounting owners are removed, no owned objects remain
and the disposable guest state is unchanged. Native reported-delivered metadata stays zero;
these throughput claims come from actual application and kernel evidence, not that counter.

The following paragraphs retain the preceding repairs and their narrower local evidence;
their pending-download statements describe those earlier checkpoints, not the above live pass.

The download candidate now connects the signed-grant/receipt actor to real helper accounting
and sender ownership. Six focused actor/controller checks, the signed Relay issuer check,
strict agent/Relay Clippy and seven receiver checks pass, including actual same-hook kernel
packet accounting and exact cleanup. Its new disposable `download-sharing` scenario measures
owner-only baseline, contributed download, contention, recovery and a paused refresh source
on the same physical receive bottleneck. It requires application bytes, actual sender-queue
bytes, both WireGuard legs, complete captures and removal of both accounting owners. No live
pass for this complete scenario has yet been obtained. Fixed, identity-free browser failure
stages were also added to distinguish the mixed-link timeout's terminal source; they preserve
the existing errors and route cleanup rather than adding a speculative retry or waiver.

The actual owned-WireGuard sender proof also passes: 29 real 1000-byte application echoes
produce 30,392 inner queue bytes at a 32,000-byte/second cap. A closed NETDEV egress gate
drops contribution without turning normal UDP sends into permission errors; expiry closes
new admission without refresh. One UDP GSO write is segmented into eight real received
datagrams and eight accounted queue packets (8,384 inner bytes). The persistent gate cannot
be retired while its owned WireGuard interface remains, and exact recovery after interface
deletion is idempotent. A separate disposable socket test checks actual capture stop/drain
and echoed fixture payloads; it does not claim the VM-only forced capture-buffer capability
or substitute for the complete protected owner-contention scenario.

The mixed-link diagnostic now enables aggregate-only native RPC timing explicitly; normal
scenarios and product startup leave it disabled. A local empty-runtime probe completes 5,000
correlated Unix RPCs at 7,861 RPC/s without instrumentation and 6,979 with it, with exact socket
cleanup. Thus connection/framing overhead alone is not a demonstrated hard 513-packet/second
limit on this host. The [profiled run on `5d3ca8ac`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34137605157)
again stalls after the LAN leg is removed from the warm route. Its fixed Client failure stage
is `TelemetryNative`: GetStatus eventually returns a transport error after an earlier period
with no delivered inner datagrams. Native RPC occupancy and CPU use are low during that stall,
so native RPC saturation is not its cause. The response barrier was released, but no completed
WAN-only response or useful aggregation ratio exists. Cleanup leaves zero owned objects and
unchanged guest state. No scheduler, congestion-control or timeout change is inferred from
the empty-runtime timing or from the later telemetry error alone.
The next diagnostic adds fixed first-rejection labels and ten-second bounded owned-path
counter/state snapshots under the same explicit opt-in. It reads the already sampled path
records, makes no extra RPC or state transition, and logs no endpoints, peer or route IDs.
Strict native compilation, five focused native checks and the opt-in RPC probe pass; these
diagnostics do not themselves repair the warm-path stall.

The [first complete download-sharing attempt on `5d3ca8ac`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34137603326)
fails before application traffic starts: signed adjacent budgets reach the activated Exit,
but the helper rejects every update, so the Relay correctly withholds session start. This
does not prove contention, recovery or refresh-expiry behavior. General teardown completes
with zero owned objects and unchanged guest state; the scenario's separate accounting-removal
proof is not reached. The same revision's Quality job finds one stale schema-enum inventory
test (27 expected versus 29 actual message types); the two new budget types are now included
in that exact-tag test rather than weakening its count or tag checks.

The downlink rejection is reproduced and repaired locally: Activate/Commit rotate the engine
operation generation while the original Prepare lineage continues to own the worker. Budget
validation now follows that post-activation distinction, preserving exact context, operation,
phase and worker ownership checks. The regression fails with the original equality and passes
with the repair; the real WireGuard sender/GSO/expiry/cleanup check and exact schema-tag test
also pass, as does strict helper Clippy. Complete owner-priority operation still awaits the
next disposable KVM run; these local results do not replace it.

The [next download attempt on `c7379ca2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34139656825)
still withholds Start, but the helper rejection advances from InvalidRequest to Unavailable:
the operation-generation repair is effective and a later dispatch boundary remains unresolved.
The full contention/expiry scenario is still incomplete. General cleanup again leaves zero
owned objects and unchanged guest state.
That next boundary is now reproduced locally: the worker coordinator omitted the typed budget
operation from its Activated/Committed transition table. Its new same-phase transition fixes
the registry regression without changing correlation or Start acknowledgement requirements.
All three focused downlink checks, including the real sender kernel proof, and strict helper
Clippy pass. Budget-only replay records now expire with the shorter signed wall/boottime
authority; an expired request is rejected before cached responses can be used. The separate
2,048-record bound does not consume lifetime replay records or the terminal Destroy reserve,
and exact in-flight tombstones remain retained. The targeted proof performs 2,724 refreshes
over a 128-leg burst and ten virtual minutes, peaking at 1,280 live budget records while
preserving critical replay and cleanup. Five downlink checks, six existing tombstone checks
and strict helper library/test Clippy pass. This is not yet a live download-sharing pass.

[Quality on `c7379ca2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34139609186)
passes, including workspace tests and strict Clippy; the same revision's CodeQL analyses
also pass after generated fixture nonces replace repeated literal signed-control nonces.
These results precede the following scheduler and budget-record changes.

A new local `run-warm-failover-probe.sh` isolates the real pinned/patched mqvpn/xquic SDK
without WireGuard or agent RPC. One retained session completes 4+8 MiB of warm traffic, a
new 4-MiB request and a 32-MiB response after one of two UDP paths is unexpectedly blackholed
with its descriptor still open. Both removal directions pass in 15--18 seconds. The final
runner check takes 16.269 seconds with all four expected/received payload hashes matching.
The source-built SDK, linked libraries, source and executable hashes are retained. This uses
explicit diagnostic application ACK/retry framing and test-only loopback TLS trust inside
a disposable user/network namespace; it is not HTTP/3, WireGuard, production TLS or alpha
acceptance. Its near-zero-RTT, continuously pumped loop does not reproduce the integrated
warm-path stall, but provides a fast real-transport basis for testing the differences.

The [profiled mixed-link run on `c7379ca2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34139658819)
identifies a concrete difference: the blackholed LAN path remains Active with its old 1,762-us
RTT and a large congestion window, while the healthy WAN is writable but has a much higher
measured RTT. Small two-per-second packets cannot fill the dead path's window, and absent ACK
progress leaves its old delivery estimate winning indefinitely. No WAN-only response or gain
ratio completes; cleanup leaves zero owned objects and unchanged guest state.

The repaired EDT estimate includes bounded overdue outstanding-ACK time after the normal
RTT/variance/peer-ACK-delay allowance, using xquic's real ACK-progress clock. It does not
change congestion control, force equal path bytes, duplicate packets or remove/reconnect a
path. The exact measured-state callback regression fails before and passes after the repair.
The real warm-session loopback probe now independently reproduces the problem with synthetic
9/19-ms one-way delays and low-rate traffic: the prior SDK delivers 0/60 small datagrams after
the fast path is blackholed; the repaired SDK delivers 59/60 with the same session and no
application retries. Its normal 4+8+4+32-MiB burst probe also passes in 6.396 seconds with all
payload hashes matching. Strict native build and shell checks pass. The retained patch hash
is `8b0a5d5aff8360f390325e618693f78e480fde116d33e58729bc6ab9aa17fa50`.
This is real transport diagnostic evidence, not the integrated HTTP/3/WireGuard bandwidth
comparison; that scenario must still pass on the new unchanged candidate.

The subsequent [mixed-link run on `efc35ac9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34142687607)
now completes the formerly stalled warm-context case: the unchanged A06 context survives LAN
loss and its real WAN-only 32-MiB HTTP/3 response completes in 53.166 seconds. The fresh LAN+WAN
32-MiB comparison also completes with the correct payload, in 50.539 seconds. Its measured
ratio is **1.052x**, below the unchanged >1.25x threshold, so useful aggregate gain remains
unproved. This is actual integrated warm-failover progress, not another standalone-probe claim.
Both aggregate paths carry response data (about 3.17 MB LAN and 36.32 MB WAN, including
WireGuard overhead). All eight bandwidth-privacy captures are complete without capture drops,
direct-exit packets or unexpected outer traffic; cleanup leaves zero owned objects and unchanged
guest state. The artifact SHA-256 is
`1f8c69fb764429fb7331a32860753cd2b27fa07a2124dcbd9a04f163d904e2b1`.
WAN-only uses Relay0 while the fresh aggregate selects Relay2 for its WAN leg, both separately
capped at 8 Mbps; this is not an otherwise identical warm-versus-fresh control experiment.
The same revision's [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34142639337)
passes strict Clippy but fails one helper test (831 passed, one failed, two ignored): the new
128-leg replay test's 64 fake process owners exhaust a shared test retirement pool when run
with other tests. Its isolated-target pass did not expose this fixture contention; production
capacity and terminal cleanup guarantees are not being relaxed to make CI green.
The repaired test uses a separate existing 64-permit retirement pool, asserts exact saturation
and complete permit return, and retains every 128-leg/replay/terminal assertion. Two parallel
replay tests, the existing bounded-pool test and strict helper library/test Clippy pass.
Only test code changes; the complete updated workspace CI result is still pending.

### Earlier checkpoints and source-change evidence

The [full v1 run on `55168536`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34045959350)
passes A01--A06 and A15, including 2.024x measured MPTCP aggregation, actual MPTCP
relay failover and the real two-path HTTP/3 exchange. A07's separate 32-MiB response
also completes after relay removal, in 57.133 seconds with matching endpoint hashes
and successful bounded QUIC drain. A07 nevertheless fails its pre-removal path-volume
gate: the surviving path carries only 205,504 bytes before removal, below the retained
1-MiB requirement, then carries 43.792 MB afterward. Both flow captures are complete
with zero drops. A08--A14 do not complete, so this is not full v1 acceptance. Teardown
leaves zero owned objects, namespaces and units, and the guest state is unchanged.

The [same-build mixed comparison](https://github.com/VOLPAROSSA/volparossa/actions/runs/34045957953)
completes both 32-MiB downloads with matching hashes and successful bounded drain:
WAN-only takes 54.804 seconds (4.898 Mbps), LAN+WAN 55.144 seconds (4.868 Mbps).
The ratio is **0.994x**, below the required >1.25x, so useful aggregation remains
unproved. Both aggregate paths carry data; all four flow and eight privacy captures
are complete with zero drops/forbidden packets. Cleanup is complete and guest state
unchanged. [Quality on the same revision](https://github.com/VOLPAROSSA/volparossa/actions/runs/34045922740)
passes workspace tests and strict Clippy. These results do not establish which runtime
stage limits throughput or prove later source changes.

The next Client runtime change processes at most one browser-QUIC response per outer
readiness turn. Already-readable application ingress can run before the next response;
response continuation remains immediately eligible within its existing 64-operation
budget, rather than being limited to one packet per timer tick. IPv4/IPv6 input turns
alternate when both are ready, and each response retains policy, expiry and native
binding checks. A real AsyncFd/UnixDatagram readiness regression fails under the old
continuation priority and passes with the new selector; five focused checks and strict
agent Clippy pass. This proves the local scheduling behavior, not live throughput gain.

The dynamic-pair fixture now also covers native HTTP/3: exact context/path/Peer/Exit
bindings survive relay removal, and all three eligible Relays stay under privacy
capture. Mixed-link requires local-LAN Relay1 plus an actual public-WAN Relay0 or Relay2;
each comparison retains its own actual path, capture and equally shaped queue bindings.
The workflow now requires a successful measured >1.25x bandwidth comparison rather than
the obsolete no-bandwidth-claim flag. Thirty-four focused fixture checks and the static
topology contract pass. These fixture changes await their unchanged-build live proof;
they do not change production selection, timeouts or the required data/gain thresholds.
A07 now establishes a fresh ordinary native route before its separate HTTP/3 application,
rather than reusing A06's warm scheduler context. Preconnect, active flow and removal must
retain that exact new context, paths and relay bindings; all pre-/post-removal byte gates
remain. A06 and A07 may choose different valid pairs, and both windows remain explicit in
A07 and A11--A13 evidence. Focused fixture checks reject context reuse, setup failures,
changed bindings and sub-threshold traffic. No scheduler equalisation or deadline extension
is introduced, and the change still awaits its live proof.

The runtime removes the redundant display-status RPC after every accepted
MPQUIC datagram. Telemetry is sampled at most once per 250 ms per route owner; initial
publication, explicit `paths` queries and maintenance still obtain fresh native status.
Every data operation retains its own live session/path, signed-flow and native response
checks. Nine focused checks and strict agent Clippy pass. The above live comparison
completes faster than the earlier `a015f17a` attempt below, but still shows no aggregate
gain; several changes between those builds prevent attributing that difference solely
to telemetry sampling. The fixture also retains bounded protocol-drain evidence
separately from application completion and requires the exact successful Client close,
not a timeout/reset.

The MPTCP acceptance fixture now measures the actual selected pair among its three
eligible Relays, rather than waiting for one named pair. Each benchmark slot retains
its exact Peer ID, namespace and interface binding; all three possible Client legs
have the same configured capacity. A02--A04 have a separate complete privacy window
covering Client, Exit and all three Relays, including Relay0, and A11--A13 require
that supplemental evidence. Real payload, both WireGuard legs, aggregation and relay
removal gates remain. Seventeen focused selection/privacy checks and the static
topology contract pass. The `55168536` run above passes A02--A04 and all five complete
supplemental privacy captures, but selects the Relay1/Relay2 pair throughout; it does
not independently demonstrate a payload-bearing Relay0 selection.

The [BBR2/reactive mixed comparison](https://github.com/VOLPAROSSA/volparossa/actions/runs/34043223406)
at `a015f17a` completes both full 32-MiB responses with independently verified payload
hashes. WAN-only succeeds after Relay1 removal in 63.976 seconds; LAN+WAN takes 66.488
seconds (0.962x), so the >25% gain requirement still fails. All four flow captures and
eight privacy captures are complete with zero drops/forbidden packets; aggregate
traffic traverses both real paths. Cleanup is complete, no owned objects remain and
guest-state hashes match. This restores the observed failover progression with BBR2,
but does not prove the subsequent EDT repair or useful aggregation.

A deterministic reproduction now identifies a separate EDT policy defect: after warm-up,
a 512-KiB historical byte deficit overrode the measured cost and sent all 32 small data
packets to a still-active black hole (100-ms RTT, 80% loss) instead of the healthy 1-ms
path. The ongoing forced byte-equalisation rule has been removed. The exact scheduler
callback now sends all 32 to the healthy path; bounded initial exploration, congestion
checks, no duplication/FEC and the live two-path/gain requirements remain unchanged.
The complete callback contract passes and patch hashes/provenance are synchronized;
actual failover and bandwidth proof still require the next full native build and live run.

The [full v1 attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34041368472)
and [mixed comparison](https://github.com/VOLPAROSSA/volparossa/actions/runs/34041367509)
at exact `3bacae04` now retain complete, zero-drop captures: the capture-stop repair is
confirmed under the live workload. Both complete the real A06 two-path HTTP/3 exchange,
but QUIC stalls after Relay1 is removed (A07 in v1, WAN-only baseline in mixed). Neither
32-MiB response completes and no gain ratio exists. V1 passes A01--A06 and A15; A08 and
the TLS repair were not reached. Both runs clean up completely with zero owned objects
and unchanged guest state. CUBIC has therefore demonstrated no benefit in this experiment;
the next build restores the previously failover-capable BBR2 on both endpoints while
retaining the reactive pump, TLS flush and complete capture windows. This single-variable
comparison distinguishes the changed congestion controller from the changed event loop;
it does not yet prove which caused the failover regression.
Subsequent diagnostics retain one bounded read-only Client path snapshot on HTTP/3
failure and a fixed role/stage plus numeric errno at a terminal native UDP receive error.
They log no endpoint, descriptor, identity or payload and do not change error handling.
The remaining helper CI failure was a source-order test's obsolete literal call marker
after startup error diagnostics were added; the test now retains its interlock/order/error
propagation checks across that spelling change. The focused test and strict helper Clippy pass.

The preceding [full v1 attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34038676673)
at `6b6d3a10` passes A01--A07 and A15 but stops at A08: both DNS transports and the
MPTCP route/descriptor handoff succeeded, then the destination TLS exchange timed out.
A09--A14 were not reached. All capture buffers were actually 8 MiB with zero drops;
the Client capture nevertheless retained one unread tail packet, so complete privacy
proof is correctly withheld. Cleanup is complete, all owned-object counts are zero and
the guest state is unchanged. A subsequent real TLS/backpressure regression reproduces
a buffered-record stall in the streaming proxy: `write_all` alone can finish before
the underlying TLS record is transmitted. The proxy now also flushes within the same
existing write deadline; four streaming tests and strict proxy Clippy pass. The A08
fixture retains its error log and available JSON on failures as well as success. Whether
this resolves the observed KVM timeout still requires the next unchanged-build run.

The [CUBIC mixed attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34039416469)
at `8df52a86` completes A06's real 4-MiB request and 8-MiB response over both LAN/WAN
paths with matching hashes. Its separate HTTP/3 captures are complete, but the general
privacy observers retained unread tail packets (Client 2, LAN Relay 2, Exit 14; zero
socket drops). That strict gate stopped the run before either 32-MiB comparison:
there is no CUBIC throughput ratio. Cleanup is complete and guest state unchanged.
The observer now stops new intake with a fixed `RET0` socket filter before draining and
reading final counters. A real disposable veth proof retains four already-queued frames
on the same socket and excludes 400 later frames, with zero drops and stable counters.
The strict reconciliation and two-second drain bound remain; eight observer tests,
nine mixed-fixture tests and the complete static topology contract pass. This fixes
the demonstrated stop race without accepting an incomplete capture.

The native process now waits on its owned Client/Exit UDP sockets and engine timers,
instead of only sampling network work on a 10-ms control wait. Borrowed descriptors
are rebuilt after each pump, reverse-queue backpressure remains bounded, and engine
activity cannot extend the absolute control-frame deadline. Strict native compilation,
nine native test targets and focused ASan/UBSan checks pass. Fixture-only HTTP/3 evidence
now includes numeric inner-QUIC loss/congestion/RTT counters at response-ready and completion;
three focused tests, strict example Clippy and a real 8-MiB disposable-loopback transfer
pass. Those counters are not outer MPQUIC path evidence, and the reactive pump still
requires an exact-source live throughput comparison.

The new [scoped crash run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34038675716)
at `6b6d3a10` **passes A14 and A15**: all 25 real SIGKILL records are retained, all eleven
helpers restart with new PIDs and republished sockets, and inherited descriptor stores are
empty before teardown. The held MPTCP request reached the exact Exit; four durable route
workers held eight descriptors before the crashes. All final owned-object/reference counters
are zero, guest-state hashes match and `cleanup.complete` is true. The complete v1 sequence
on the same revision stopped at A08 above; the scoped pass is not an all-A01--A15 claim.

The earlier [complete v1 attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34036578734)
at `fc3ec96a` reports A01--A13 and A15 success on one unchanged build, including A06 MPQUIC
and A08 DNS after the republication fixes. A01--A10 and A15 have passing evidence, but the
raw A11--A13 privacy captures dropped packets (Client 428, Relay1 786, Exit 434); their
predicates omitted that completeness check. Those three success flags must not be treated
as complete privacy proof. A06/A07's separate captures have zero drops. The explicit scenario
failure is A14 helper restart after forced crashes, not the earlier route-authority join.
Both restart recovery and complete privacy captures remain acceptance work. Final owned objects,
namespace references and stored descriptors are zero and guest-state hashes match, but
`cleanup.complete` remains false because restart recovery failed. The separate
[crash run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34037176994) at `7a414a78`
retains all 25 actual SIGKILL records (11 agents, 11 helpers, three native processes).
All four custody-bearing helpers reach `SettleMayOwn` then reject restart-reaper
authentication; the new diagnostics narrow the boundary without weakening recovery.
This is not an all-A01--A15 pass or completion of the local-link/capacity extensions.

The restart sandbox was dropping `CAP_NET_BIND_SERVICE` while the shared parent attestation
requires it, unlike the ordinary worker's correct pre-identity setup. Restart now retains
the same bounded capability set; the final identity/capability checks are unchanged. The
existing restart regression fails before the fix and passes after it. Two focused checks,
strict helper Clippy and a disposable real-kernel bounding-mask witness pass (`0x1100`
after the erroneous drop versus required/retained `0x1500`). The subsequent scoped live
run above now proves actual systemd recovery with this fix.

A11--A13 now explicitly reject absent, null or nonzero capture-drop counters. The collector
also verifies its bounded 4-MiB receive buffer, reads interfaces in fair 128-frame rounds,
drains queued packets for at most two seconds on stop and reconciles final kernel packet
totals against read/lost packets. A disposable 500-frame reproduction recorded 185 read and
315 dropped with the old effective 425,984-byte buffer. Twelve negative predicate cases,
fair-drain/tail checks, nine mixed-fixture checks and the static KVM contract pass. Only the
next corrected live v1 run can establish complete captures under the full workload;
the `6b6d3a10` run above has zero drops but an unread final tail.

Direct-LAN reconnection now has two reproduced transport fixes. With two IPv4 QUIC
listeners, a real authenticated reconnect after LAN down/up previously arrived from the
public listener's address. Private direct-IP Dialer connections now use a fresh socket so
the kernel selects the source; four real reconnects retain the LAN source. Public/NAT,
Circuit and Listener-role options are unchanged; this grants no new address authority.
Unexpected closure also previously left a configured listener permanently absent. The
event pump now reopens only its exact original request, with 32-entry and one-second retry
bounds. Shutdown disables retries before draining and closes endpoints afterwards, retaining
existing control connections during retirement. Both disposable-network reproductions,
two focused option/bounds checks and joint strict discovery/agent Clippy pass. This is not
yet a passing mixed-link aggregation run or physical-radio evidence.

The [next mixed-link run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34037899646)
at `54f65ede` confirms restored LAN discovery and a fresh two-path route. Both 32-MiB HTTP/3
responses completed with matching hashes, but LAN+WAN took 155.832 seconds versus WAN-only
68.091 seconds (0.437x), so no gain is claimed. Its eight privacy captures have zero drops
and cleanup is complete. The separate aggregate path captures hit their older 131,072-frame
limit; that bound now scales finitely to 524,288 for the declared 32-MiB response, retaining
truncation rejection. Three boundary checks and the static KVM contract pass. A single-variable
congestion-control comparison now selects CUBIC only for true MPQUIC, leaving general-UDP BBR2,
EDT scheduling, path requirements and the >25% gain threshold unchanged. The adapter compiles
against cached native dependencies and nine native checks pass; the exact-source live build
and throughput comparison remain required. This is an experiment, not a claimed speed fix.

The [v1 run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34034165008) at `83264e55`
passed A01--A05 and A15, but stopped selecting A06's required benchmark pair. Eight established
MPQUIC contexts used other valid pairs. Both desired native probe legs also completed, followed
by rejection at the post-probe authority join; the exact guard was not logged on this build.
A07--A14 were not reached. All 169 exact cleanup completions succeeded and no owned objects
remained. This attempt did not prove A06 or the advertisement-refresh/handoff integration.
The reproduced republication defects are now fixed at both joins: immutable selected/native
evidence can continue with a newer live same-Exit/full-policy authority, and ordinary pending
RPCs survive a verified refresh without losing their original control provenance or deadlines.
Real signed-refresh and affine-handoff regressions failed before the changes and pass after them;
targeted withdrawal, policy, expiry, replay and endpoint-substitution checks and joint strict
agent Clippy pass. The later `fc3ec96a` run above confirms A06 and A08 progression with these fixes.

The [uplink transition run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34034024459)
at `83264e55` passed all three phases and six protected application routes without restarting
the four participant daemons. Independent-uplink loss withdrew Exit authority; the affected
node could consume through others, then resumed Exit contribution on a fresh route after
restoration. Complete zero-drop captures and unchanged guest-state cleanup support this scoped
configured-interface result; it is not general Internet-health or unknown-interface discovery.

The [full-agent simulated Wi-Fi run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032559440)
at `4500d602` passed: the offline daemon consumed and relayed application traffic concurrently
over its agent-created mesh interface, with exact hashes, two-leg packet evidence and complete
cleanup. This is simulated-radio software integration, not physical-radio or bandwidth evidence.
The same build's [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032489881)
passed formatting, strict workspace Clippy, workspace tests, dependency/license checks and the
non-mutating harness. It explicitly reported that the ordinary runner could not enter the
egress namespace test; that check is mandatory in the separate KVM uplink scenario.
The same revision's [v1 attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032557009)
passed A01--A07 and A15 but stopped at A08; A14 was not reached. This time the DNS route's
Client Prepare, Activate, native probe and Commit succeeded, and exact Destroy returned in
169 ms. The later actor-authority join rejected the route. Thus the reproduced helper cleanup
blockers were passed, but a usable DNS response and the remaining acceptance sequence were not.
Final cleanup left zero owned objects, namespace references and stored descriptors.

The `crash-recovery` scenario now runs the unchanged A14 held-MPTCP, 25-SIGKILL and
eleven-helper-restart sequence directly, without waiting behind A01--A13. Its separate
`crash-recovery.json` reports A14/A15 only and cannot claim complete alpha acceptance.
Load-only, scoped-report rejection and topology-contract checks pass. Its
[first live run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34035285152) at `1150737c`
proved the held MPTCP request through the exact Exit and correctly inventoried four route workers,
one ingress worker and eight durable descriptors. It then failed helper restart: the four
custody-bearing helpers repeatedly stopped unsuccessfully; the seven empty helpers did not.
Final objects/references/descriptors were zero and A15 passed, but A14 and `cleanup.complete`
remain false. The fixture now preserves all individual crash results in their aggregate before
the restart gate and exports a failed restart's observed state, rather than losing that evidence.
Fixed, identity-free authority-join stage diagnostics also retain the existing rejection behavior.
The restart-reaper parent also retained a duplicate child IPC descriptor in `Command` after
spawn. An immediately rejected subprocess therefore hid EOF until its deadline: the focused
reproducer failed at 2.01 seconds before release and completed immediately afterwards. Both
restart-reaper spawns now release that duplicate. This does not identify the earlier fast A14
startup rejection. Closed startup/custody phase, reason and errno diagnostics now retain its
failure boundary without logging identities or changing recovery gates. Thirty-two focused
server/reaper/custody checks and strict helper Clippy pass; live restart proof remains pending.

The retained [complete v1 attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33989949727)
at `dbb89962` has finalized A01--A13 and A15 success flags on one unchanged build.
Its older A11--A13 captures did not export `packet_socket_drops`, so their completeness
cannot be established retrospectively; those flags are not a complete privacy proof.
It stopped before A14's forced crashes: the inventory counted 18 durable route-worker namespaces
plus the separate live ingress namespace, but demanded two durable descriptors for all 19.
The actual 36 descriptors cover the route workers; the ingress worker has a different lifetime
owner. Its real held MPTCP request reached the destination through the exact Exit. A14 remains
failed until exact worker-class inventory and the actual SIGKILL/restart sequence pass.
All measured remaining objects, worker namespace references and FD-store descriptors were zero,
and guest-root state hashes matched. `cleanup.complete` is nevertheless false because the A14
proof did not complete. This is not an all-A01--A15 alpha pass, nor proof of the newer extensions.
The exact route-versus-ingress worker classifier is now integrated, including real disposable
veth/WireGuard inventory checks. The [next complete attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33991871530)
at `590378a9` passed A01--A07 and A15, but stopped at `A08_ALLOWED_DNS_UDP_NOT_PROVEN`;
A09--A14 were not executed. Its MPTCP aggregation measured 14.113 Mbps against a 7.046-Mbps
single-path baseline (2.003x), with exact 32-MiB hashes and independent path evidence. This is
the bounded v1 benchmark, not a LAN/Wi-Fi speed-gain claim. Cleanup left zero owned objects and
unchanged host-state hashes. The DNS request never acquired its route: its preselection probe
reached the Exit, but the Relay's exact Destroy timed out before the terminal result could
return. A real isolated Relay lifecycle reproduced a cleanup defect: the nftables deactivation
transaction tried deleting INPUT rule handles from the FORWARD chain, so Linux rejected the
atomic batch with ENOENT and retained the active fence and both links. Deletions now use each
rule's exact owning chain, preserving handle/generation binding. Eight real Prepare/Activate/
Destroy cycles now pass with both links absent after each cycle; the encoder regression and
strict helper Clippy also pass. This fixes the reproduced defect; the complete run must still
verify A08 and the separately observed ten-second coordinator retirement behavior. Eight fixed,
identity-free cleanup checkpoints identify the stage if that behavior recurs. The DNS parser
and acceptance gate are unchanged. A14's actual crash sequence still has no pass.
The [following complete attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33994616201)
at `092da0fb` passed A01--A07 and A15. All 55 exact Destroy responses returned within
0.498 seconds, without the former ambiguous ten-second timeout. A08 reached the next stage:
Client activation crossed from 22:14:29.971 to 22:14:30.002 UTC, but its actual WireGuard
handshake occurred in second 29. Commit incorrectly demanded the later completion second.
The helper now retains the pre-dispatch activation lower bound; a clock-advance regression
fails before the fix and passes after it, with existing bidirectional-growth and expiry checks
unchanged. Later whole-daemon cleanup also exposed historical FD-store snapshots rejecting
independent sibling routes. Same-runtime exact removal now confirms the current inventory
under the mutation gate and preserves every unrelated descriptor; restart inventory ordering
remains strict. Both sibling-publication and sibling-removal reproductions pass. Eleven focused
helper checks and strict helper Clippy pass. These are implemented fixes awaiting a new live
run, not an A08/A14 pass. A09--A14 were not executed in this attempt; final disposable cleanup
left zero owned objects and matching guest-state hashes.
The same revision's [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33994604081)
found three source-boundary assertions still expecting a private test module after its fixture
helper became `pub(super)`. Their exact boundaries are updated, preserving the custody checks
and negative mutations; all three now pass locally.
The [next complete attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33996311895)
at `d2d75dcc` again passed A01--A07 and A15, but did not finish A08 or execute A09--A14.
The prior exact Client route retired in 396 ms. A subsequent Client Prepare succeeded, but
the Relay's cleanup of an older expired worker stalled at `CLEANUP_DEAD_WORKER_RESOURCES`;
its ten-second timeout prevented the new route from activating. Two causes now have direct
RED-to-GREEN reproductions: kernel timeout removed the live authorization element while leaving
the exact owned Relay table/rules, and the parent's retained `Command` stdin duplicate masked
an early reaper exit until the protocol deadline. Post-reap cleanup now accepts that exact empty,
closed successor without restoring forwarding authority; the duplicate is dropped after spawn.
The real expired-fence cleanup passes, early child exit returns in 0.01 seconds rather than the
two-second test deadline, and the real helper executable completes credential/namespace-FD
cleanup in a disposable namespace. Foreign/extra objects and active authorization without a live
element remain rejected. The complete live sequence still needs to confirm these fixes.
Final disposable teardown reported zero remaining objects.
This revision's [Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33996288841)
passed formatting, dependency checks and strict Clippy. Its new egress namespace test failed
before test entry because the runner denied writing `uid_map`. The test now distinguishes only
byte-exact pre-entry policy denial from an actual entered-child failure, with an explicit
`SKIPPED_EGRESS_NETNS_PROOF` diagnostic. The mandatory KVM mode does not permit that skip.
All four focused egress tests passed locally in mandatory mode, including real capability-free
binding, link loss/return and rejection of fallback; strict linux-uapi Clippy passed.
Benchmarks now select and record a suitable real route before starting
payloads; committed MPTCP paths are Reachable metadata, never a substitute for kernel subflow
and packet evidence.

### Earlier integration evidence and corrections

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

Additional user requirement (2026-09-08): replace arbitrary fixed product limits on the number
of direct/Internet peer connections with adaptive connection management. Retain additional
connections when measured throughput, capacity, stability or useful cache reach improves;
retire unhelpful connections and scale back under owner demand or resource pressure. This
applies to connection policy, not unbounded allocation or permission to exceed a transport's
actual protocol/backend capacity. Control peers, local neighbors, active route paths and cache
workers need separate accounting. Adaptive cache workers, HTTPS provider batches, resource-derived
control admission and mesh-neighbor integration are described above. Native transport ceilings and
the defensive mesh-observation boundary remain; the complete limit-removal requirement is not done.

The functional-development target now includes direct Ethernet and Wi-Fi peer links alongside
Internet underlays, Internet access for a node without its own uplink through reachable
contributors, and parallel use of independently useful local and Internet paths. Contribution
is mandatory according to available capabilities. Owner traffic takes priority over contributed
traffic; spare capacity must be measured and enforced, not inferred from configured limits alone.

- [x] Local on-link authenticated discovery and two-leg datapaths without a client default route (IPv4 disposable live proof below).
- [x] Per-path underlay/interface binding for simultaneous local and Internet paths (genuine MPQUIC transfer below; not a bandwidth-gain claim).
- [ ] Measured useful throughput gain from combining independent LAN and Internet paths.
- [x] Full-agent direct mesh discovery, concurrent offline consumption/contribution and teardown on simulated Linux radios.
- [ ] Driver-supported direct Wi-Fi link setup, teardown and real-radio transfer proof.
- [ ] Measured spare-capacity sharing with owner-priority enforcement under competing traffic.
- [x] Offline participation and configured-uplink loss/recovery without recursive overlay-as-exit egress (IPv4 live proof below).

The mixed-link fixture now includes a real HTTP/3 bandwidth comparison: a two-path native MPQUIC
session loses its LAN link before a held 32-MiB response is released, then a fresh LAN+WAN
session downloads the same size. Both client-facing Relay links are individually capped at
8 Mbps. Passing requires more than 25% gain, exact application/Exit hashes, received data on both
aggregate paths, exact context/path bindings, zero capture drops/leaks and complete cleanup.
Two fixture-profile Rust checks, seven focused observer/validator checks and strict example
Clippy pass. No throughput gain is claimed until the actual comparison passes in the VM.
The [first comparison attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032560730)
at `4500d602` stopped before A06: normal route reselection called `wait_disconnected`, but that
shared function was defined only inside the A01 block omitted by this scenario. It and the
shared transient-error classifier now load unconditionally from `benchmark-selection.sh`,
with their behavior unchanged. Eight focused fixture checks and the static topology contract
pass. The attempted run cleaned all owned objects and preserved its guest-state baseline;
it produced no new throughput measurement.
The [next comparison attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34033641848)
at `6116db05` passed the real A06 LAN+WAN HTTP/3 transfer and privacy checks, then stopped
while selecting its baseline: Relay2 activation returned `Kernel(6)` after confirmed rollback.
No bandwidth ratio was produced. The baseline now reuses only the exact still-active A06
context, paths, Relays and Exit, with normal new-flow expiry checks; the aggregate case still
requires a fresh selected context. Nine focused fixture checks pass. This removes unnecessary
baseline reconnection, not the observed kernel failure or the requirement for measured gain.
The [following comparison](https://github.com/VOLPAROSSA/volparossa/actions/runs/34035286510)
at `1150737c` passed A06 and delivered the complete 32-MiB WAN-only baseline response in
64.469 seconds with matching application/destination hashes. After LAN restoration it could
not acquire an aggregate route: candidate sampling repeatedly rejected the snapshot before
the route-authority join. Therefore no aggregate transfer or speed ratio is claimed. Cleanup
completed with zero owned objects and unchanged guest-state hashes.

The next uplink-transition runtime uses optional `network.independent_egress_interface` for an
already authorized IndependentInternet Exit. Bounded read-only netlink observations track that
interface's carrier, address and main-table default route. New TCP/general-UDP/browser-QUIC
destination sockets bind to the exact interface before connecting, without an unbound fallback.
Loss or interface replacement withdraws Exit authority and stops its exact runtimes; separate
Client/Relay owners and configured role consent remain. Recovery waits for exact old-route
cleanup and republishes under the active policy. A LocalOnly configuration cannot enable Exit
through this option. It does not probe Internet uptime, change system DNS, discover a new ISP,
or promise independent resolver routing.
Focused checks passed: actual capabilities-free socket binding in a disposable network,
link/default loss and return with an alternate default left unused, a real protected UDP echo
followed by cancellation and exact listener release, signed-role/policy withdrawal and recovery,
and interface-replacement cleanup gating. Strict Clippy for the changed packages passes.
The `uplink-link` multi-node fixture now holds an actual application socket across withdrawal,
requires signed Exit-role loss/recovery without restarting the daemons, and exercises six
consume/contribute flows over the three phases with payload, source, path and cleanup evidence.
Its five focused validator/preview checks and script contract pass. The
[first live attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33994615937)
at `092da0fb` stopped before application traffic or uplink withdrawal:
`UPLINK_LOCAL_CONTRIBUTION_ROUTE_UNAVAILABLE`. Ordinary Client Disconnect incorrectly requested
whole-helper cleanup, including other roles, and an older route's historical FD-store snapshot
rejected a newer sibling. Client Disconnect now retires only its exact retained owner, reports
pending cleanup without losing that owner on cancellation/timeout, and blocks replacement
until confirmation. Unrelated Relay/Exit roles and newer context projections are untouched.
Four focused Client tests and strict agent Clippy pass; the independent-order FD-store fix is
described above. The failed live attempt cleaned all owned objects with matching guest-state
hashes. The complete transition remains unproven; unconfigured uplink-monitor behavior is unchanged.
The [subsequent uplink attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33996312669)
at `d2d75dcc` reached real traffic: 56 C-to-A-to-X echoes and 16 A-to-C-to-B echoes with their
expected Exit sources. Exit authority was withdrawn 378 ms after uplink loss. Three distinct
challenges on the same old application socket produced no echo and no destination receipt.
The packet observer then failed on `ENETDOWN` from the deliberately disabled B uplink, leaving
the complete initial-phase capture and later loss/recovery phases unproven. Only the explicitly
declared interface transition now permits that error, retaining the same packet socket and
requiring the exact ifindex/state sequence in the report. Six focused checks and a real disposable
AF_PACKET down/recovery test pass, including continued observation of another link and zero
packet drops. Failed-run cleanup left zero objects and matching guest-state hashes.
The [following uplink attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032558106)
at `4500d602` retained complete zero-drop captures through the declared link loss. Exit authority
was withdrawn 140 ms after the loss baseline, and the same old application socket's challenges
received no replies. Initial consumption/contribution and both flows during the outage had
matching application hashes; the uplink-less node could consume through the offline Relay.
The run stopped only after the independent link returned and its Exit role was advertised
again: the other consumer repeatedly received preselection authority rejection instead of a
restored route. Its cached forwarded Exit advertisement was not refreshed during the three-minute
selection window. Recovery remains unproven; all owned objects were removed and guest-state
hashes matched.
The scheduler now refreshes still-valid forwarded Exit capabilities every 30 seconds through
the existing authenticated control Relay. The three-lineage limit, affine capability lifetimes,
request bounds and replay/cooldown checks remain unchanged; only accepted signed ingest updates
the refresh clock. The old suppression is reproduced with real signed 120-second capabilities;
eight focused scheduling/lineage checks and strict agent Clippy pass. The complete live
restoration sequence still needs a successful rerun.
That [complete rerun](https://github.com/VOLPAROSSA/volparossa/actions/runs/34034024459) at
`83264e55` now **passes**. Its six protected UDP routes delivered 135 real echo datagrams with
independently checked application/destination hashes. Initially and after restoration, C used
A as Relay to X while A used offline C as Relay to B; during B's outage, B instead consumed
through C to A's independent Exit. Each phase had more than 3.10 seconds of actual flow overlap.
The exact configured `r2d` ifindex stayed 62 across UP--DOWN--UP/default removal and return.
Exit authority withdrew 58 ms after the loss baseline; verified advertised roles changed
111--011--111. Three new markers on the original A-to-B application socket produced no replies
and no destination receipt. A fresh ordinary selection found no ready route to withdrawn B;
no incoming Exit-grant rejection is claimed because none was observed. Restoration used a new
context with the same four agent PIDs. All twelve capture records were complete with zero
drops, direct-exit packets or plaintext leaks; cleanup removed all owned objects and preserved
identical guest-state hashes. This proves one explicitly monitored IPv4 uplink, not automatic
discovery of previously unconfigured interfaces, Internet-wide reachability or physical-radio
recovery. The offline node never acquired a main default route or an Exit role.

The first implementation now carries explicitly signed RFC1918/ULA endpoint scope through
authenticated connection provenance, selection, endpoint leases, reservations and helper
Prepare/Activate. Each WireGuard lease has its own underlay: Client-facing LAN and Exit-facing
WAN can differ at the same Relay. LAN preparation requires an assigned local address, a unique
connected route and a read-only exact kernel source-to-peer lookup; activation rechecks that
binding. Public-IP validation remains unchanged. Focused checks cover scoped canonical encoding,
local provenance, planner-to-preprobe consumption, mixed-leg signed helper activation and kernel
route parsing. These initial checks were not live LAN packet evidence; the later passing runs
below now support the two scoped datapath items.

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
checks passed before the later live giving-and-taking result recorded below.
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
The common local/mixed selection blocker is now corrected: discovery fetches at most three
current authenticated control lineages per Exit, refreshing near-expiry slots without briefly
enrolling a fourth. Each newly captured snapshot chooses exactly one consistent signed Exit
lineage before building its affine subjects; the Exit is never weighted multiple times, and
existing operations do not migrate. Four fetch checks, seven signed/projection checks, formatter
and strict agent Clippy pass. Runs
[local-link](https://github.com/VOLPAROSSA/volparossa/actions/runs/33990931726) and
[mixed-link](https://github.com/VOLPAROSSA/volparossa/actions/runs/33990931649) at `f1881887`
both **passed**. The offline node consumed through `C -> R2 -> X` while contributing the actual
`A -> C -> R2` Relay path: both streams received 16 exact 319-byte echoes with matching hashes,
3.115 seconds of overlap and positive packet evidence on both WireGuard legs. The same offline
daemon retained Client+Relay/no-Exit roles and no physical default route. All four observers
reported zero drops/direct Client--Exit packets/plaintext leaks. Cleanup left zero owned objects
and identical host-state hashes. This is real simultaneous IPv4 Ethernet/LAN give-and-take,
not physical-radio, IPv6, automatic uplink-loss recovery or bandwidth-aggregation evidence.

The mixed run transferred a real HTTP/3 4-MiB request and 8-MiB response with matching client/
destination hashes through one LocalOnly LAN Relay and one public Relay to the same Exit. Both
native paths were Active; the independent Client and Exit captures each recorded 9,089,824
WireGuard data bytes on the LAN path and 9,534,080 on the public path. The LAN Relay retained
no ASN, public prefix, default route or Exit role. Privacy captures passed and exact cleanup
left zero objects with unchanged guest state. No single-path QUIC fallback or aggregate-speed
claim is made. Application, path-count, privacy and cleanup requirements were not relaxed.
Client native preselection and single-path Exit Ready also carry exact observer-bound local
interface hints into their helper Prepare operations. They cannot rely on a public default route
on a LocalOnly node. Multi-path Ready now collects all signed Permits, dispatches Relay Ready
concurrently, and verifies replies with the same sequential replay owner. The Exit waits for
the complete authenticated ordinal/endpoint set before one shared helper Prepare, requiring
exact local traversal hints for each LAN path. Partial sets expire without helper allocation.
Nine focused tests, the mixed-plan real helper encoder check and strict agent Clippy pass;
the subsequent `f1881887` run above supplies the mixed-path application proof.
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
focused report/observer checks and shell/workflow contract passed before its first live attempt.
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

The first explicit Debian `wifi_mesh` runtime and its full-agent overlay have passed the
disposable simulated-radio proofs below. Physical-radio transfer remains open.
The user has no spare Linux devices or Wi-Fi adapters available at present (2026-09-06), so
physical-radio acceptance is explicitly deferred; simulated-radio results do not fill that gap.
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
The next `wifi-link` vertical now composes the actual agents with those simulated radios:
mesh-only mDNS plus exact authenticated transport discovery occurs before the other agents start;
their later arrival enables the normal signed-capability candidate pool. The offline node then
consumes and contributes real protected traffic concurrently. An Ethernet
contact remains for distinct local-prefix diversity. The actual contributing flow must traverse
the mesh, with per-interface WireGuard transport counts and station counter growth; consumption
is attributed only to its observed selected underlay. Mesh survives route-only Disconnect and
must disappear on agent shutdown before helpers stop. Four parser/report/preview checks and the
existing shell/workflow contract pass; [its first live run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33990931641)
at `f1881887` stopped during fixture configuration, before agent startup: the non-mesh
configuration branch returned the previous shell condition's nonzero status. A direct shell
regression fails on the old code and passes with explicit success for non-mesh nodes; all five
Wi-Fi fixture checks pass. Simulated radios were removed and guest-state hashes matched.
The [corrected full-agent mesh run](https://github.com/VOLPAROSSA/volparossa/actions/runs/33991872480)
at `590378a9` installed both real agent-owned mesh interfaces, then failed at
`WIFI_LINK_MDNS_AUTHENTICATION_UNAVAILABLE`: both authenticated peer views stayed empty.
The observer also wrongly required response source port 5353, although pinned libp2p mDNS uses
an ephemeral sending port. Its corrected exact-peer/interface filter and bounded early station
diagnostics pass focused fixture checks. Both status artifacts actually retained one active
transport peer: the early fixture incorrectly waited for signed candidate rows whose normal
privacy partition requires at least three providers, while only two agents had started.
The corrected ordering requires exact authenticated PeerID/mesh-IP events, mDNS and kernel
peering first, then preserves the full signed-role check after the remaining agents start.
Six focused fixture checks pass; the real application run still needs to pass. All mesh/radio
objects were removed and guest-state hashes matched; the backend-only radio pass is unchanged.
The [next full-agent mesh attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33993298958)
at `48c1fb6a` passed that association stage: eight exact remote mDNS records and both expected
authenticated mesh PeerID/endpoints were observed before the other agents started. Later
signed roles were present as well. It then failed at `LOCAL_LINK_NATIVE_ROUTE_UNAVAILABLE`:
both mesh nodes' Client and Relay Prepare operations failed before application traffic, while
the other nodes could prepare. The helper rejected a legitimate nested `IFLA_PROP_LIST` holding
the parent WLAN's alternative name. The observed Linux attribute shape reproduces the decoder
failure; bounded recognition of that exact property structure now passes all 18 focused decoder
checks without changing primary interface, source or ownership validation. All mesh/radio
objects were removed and guest-state hashes matched. Full-agent application traffic over the
mesh still needs a corrected live run.
The [next mesh attempt](https://github.com/VOLPAROSSA/volparossa/actions/runs/33994615930)
at `092da0fb` exceeded the outer 2400-second guest-execution limit and exported only a VM console.
It therefore supplies no finalized application, privacy or cleanup report; earlier association
evidence cannot be substituted for this run. The runner now exports bounded existing logs and
helper process diagnostics after a timeout, even when the normal archive is absent. It preserves
the original failure status and explicitly records cleanup/host state as unverified. Four focused
collector/driver tests and the script contract pass. The 2400-second bound is not removed, and a
partial diagnostic archive cannot count as a successful or fully cleaned topology.
The [complete mesh run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34032559440)
at `4500d602` now **passes**. Two agent-created interfaces reached kernel ESTAB at 2412 MHz;
five matching mDNS records and both authenticated peer/mesh-address events preceded the other
agents, without mutual bootstrap contacts. The same offline Client daemon then consumed over
mesh through Relay0 to the Exit while relaying Relay0's traffic over mesh and Ethernet to
Relay2's independent Exit. Both flows delivered 16 exact echoes with matching application and
destination hashes, correct Exit source addresses, both WireGuard legs and 3.120 seconds of
overlap. Each mesh direction carried 65 observed WireGuard packets; both station byte counters
grew. The offline node retained no main default route or Exit role. All four captures were
complete with zero drops, direct-exit packets or plaintext leaks. Route Disconnect preserved
mesh, agent shutdown removed both interfaces before helper shutdown, and final cleanup left
zero interfaces/radios/owned objects with hwsim unloaded and identical guest-state hashes.
The native delivered-byte metadata remained zero; application and packet measurements provide
the actual traffic evidence. This proves simulated mesh plus Ethernet, not physical radios,
Wi-Fi-only operation, MPQUIC aggregation, mobile support or added bandwidth.
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
  authenticated libp2p establish/address-change/close lineage under the original
  384-global/four-per-peer ceilings (subsequently extended by resource-derived control admission
  as described above).
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
