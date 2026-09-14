# Decentralized cooperative agents and automatic policy governance

Requested extension, 2026-09-14. **Design and implementation scope, not delivered functionality.**
The user explicitly chose fully automatic network-policy decisions, without a required human
approval step. This extends the functional-development alpha; it does not replace unfinished
network/content work or make existing checkpoint results cover machine learning.

## Requested outcome

Capable participating nodes autonomously train agents, exchange their reusable artifacts and
cooperate on individual users' tasks as one decentralized service. The same network maintains
shared content whitelist/blacklist decisions and checks, repairs or excludes defective agents.
Participation remains capability-based: an idle device can contribute useful work without
every device training a large model or retaining every model. No permanent central compute,
training, task-dispatch or decision authority is part of the target.

The requested positive principles are **Humilitas, Humanitas, Mansuetudo, Diligentia,
Liberalitas, Temperantia and Castitas**. The negative principles are **Superbia, Invidia,
Ira, Acedia, Avaritia, Gula and Luxuria**. The user clarified their two distinct applications:
**concrete allowed/prohibited content rules** for the whitelist/blacklist, and **general
behavioral principles** for agents and their training. The user supplied the concrete examples
below on 2026-09-14. Jurisdiction, category boundaries and conflict rules still need specification;
no numerical virtue score or automatic "good person/bad person" classification is implied.
Describing or critically discussing a vice is distinct from facilitating harmful conduct;
naming a principle is not yet a reproducible classifier or an implemented policy rule.

## Agreed content-policy examples

The intended distinctions are concrete, not a blanket ban on every activity described as a
vice. These are requirements for the future automatic engine, not new active destination rules.

| Treatment | User examples | Required distinction |
| --- | --- | --- |
| Prohibited | Illegal content/conduct, unauthorized piracy, scams/fraud and child sexual abuse material (CSAM) | Refuse the prohibited material and tasks facilitating that conduct. Lawful reporting, prevention, victim support, legal education and critical discussion are not the conduct itself; this does not authorize distributing illegal source material as "research". |
| Requires contextual assessment; no blanket verdict agreed yet | Lawful adult pornography, gambling, harmful compulsive/low-value social-media use and radicalizing forums/chat groups | Distinguish legal consensual adult material from exploitation; licensed lawful activity from prohibited activity; ordinary discussion from incitement, threats or recruitment to violence. A platform name, unpopular opinion or political/religious identity is not enough evidence. |
| Remains allowed; constructive alternatives may be suggested | Lawful shopping/overconsumption, including Amazon, and ordinary viewing/posting on X/Twitter, Reddit and Facebook | Do not turn "unnecessary," environmentally undesirable or unwise spending into an automatic ban. Advice is transparent and dismissible, not covert throttling, forced redirection or public profiling of users. |

An assessment must distinguish the **content or requested action** from a **pattern of use**.
A short video is not inherently evidence of harmful compulsive use. Personalized wellbeing
suggestions require an explicit local feature; they must not introduce default browsing-history
retention, cross-node behavior dossiers or a model inferring moral worth from private activity.
Agent principles guide honesty, restraint, diligence and non-exploitation while following these
content boundaries; they do not grant authority to punish disagreement.

"Outside the law" needs an applicable, versioned legal basis, not whichever country's law a
peer happens to assert. EU and national laws can differ, as the
[European Commission explains](https://digital-strategy.ec.europa.eu/en/factpages/tackling-illegal-content-online-digital-services-act).
The user selected **Netherlands/EU as the common network baseline, plus applicable local exit
restrictions** on 2026-09-14. A local restriction must not expand the common network allowance;
an exit enforces the intersection, not whichever rule is more permissive. This choice is a
design requirement, not implemented jurisdiction discovery or a legal determination for a node.
The future decision records must distinguish a legal prohibition
from a separate network-community rule and identify their authority and scope. This document
does not determine intermediary status, applicable liability or jurisdiction for each node.

Whitelist/blacklist decisions cannot promise a perfectly "clean" cache or eliminate exit risk.
Original signatures and content hashes establish provenance/integrity, not legality, consent or
redistribution rights. An approved hostname does not approve every object behind it. Public
chunk admission therefore needs a decision bound to the original object's identity/version;
an unknown object or unsigned peer accusation is not a valid approved/forbidden decision.
Revocation must stop new serving/redistribution of the affected local object without allowing a
remote model to delete unrelated files. Existing copies on uncooperative peers cannot be
guaranteed erased.

The engine must not break end-to-end encryption or expose private prompts/messages to public
assessors to manufacture a universal filtering claim. How untrusted encrypted publications are
admitted without becoming an unchecked shared-storage channel remains a required design and
implementation problem. Cache custody currently verifies bytes and publication provenance;
it **does not implement** the requested moral/legal content classification. Use synthetic,
non-actionable fixtures and authorized benign corpora for development; never obtain real CSAM
or illegally redistribute copyrighted works to build the classifier's tests/training set.

## Reuse and separation

The user explicitly confirmed on 2026-09-14 that autonomous training should exploit the
existing distributed cache. This is a **required integration**, not an automatic property of
the current cache or of local adapter training. Cache model weights, compatible adapters,
eligible training packages and evaluations once, then prefer work on nodes already holding
the required chunks. Otherwise retrieve only the missing chunks through the protected content
datapath; use the same spare-capacity sharing budget as ordinary cache traffic.

Eligibility for serving an object is not permission to train on it. An automatic training
job needs an explicit dataset identity, origin, redistribution/training rights, privacy class
and compatible model revision; arbitrary cached browsing content, private messages or peer
instructions are not default training inputs. Dataset selection, deduplication and diverse
sampling must avoid rewarding peers for flooding the cache with copies of one source.
Validate candidate updates against held-out data before activation, with bounded rollback or
quarantine; signature/hash checks alone do not detect poisoned or low-quality models.

The user additionally required on 2026-09-14 that the cache must **not define the available
knowledge or training corpus**. Select eligible sources/examples for relevance, provenance,
coverage and diversity before deciding how to acquire them. Prefer existing verified chunks
when advantageous, but fetch missing/fresh chunks from other holders or the original approved
publisher/origin. A cache miss is not a reason to silently substitute a more popular cached
source. Preserve original authority, expiry, access rights, privacy and contribution budgets
on fallback; do not invent arbitrary Internet egress or unlimited background crawling.
Ordinary cache-only mode is an explicit offline/resource choice, not the autonomous-training
default. A future selector must measure coverage and sample less-represented eligible sources;
cache locality may influence execution placement, not whether a relevant source is considered.
Origin fallback alone does not prove freedom from selection bias. This selector and generalized
external-dataset ingestion are still required work, not implemented by the initial adapter codec.

- Reuse content-addressed chunks, original signed manifests, protected peer retrieval and
  custody for public model weights, compatible updates and evaluation artifacts. Caching an
  artifact must not activate it. A signature proves provenance, not model correctness.
- Separate a model's data from its runtime and tools. Use an explicitly supported, versioned
  model/operator format in an isolated worker; do not execute downloaded scripts, plugins,
  pickle objects or native libraries. No automatic executable-code update channel is implied.
- Discover short-lived compute capabilities through the existing peer model, not a central
  worker catalogue. Input/output sizes, task lifetime, hardware needs and privacy requirements
  are part of the job contract; public indexes contain neither prompts nor private documents.
- Use compatible model families and bounded local updates. Arbitrary agents or weights cannot
  simply be averaged into a single model. The shared "brain" is coordinated training and task
  execution, not a claim that all users' private memories become globally shared state.
- The network supervisor `volparossa-agent` remains separate from these AI workers. Workers
  receive no helper privileges, node signing keys, home directory, browsing history or arbitrary
  tool authority. External task effects require narrowly scoped user-authorized capabilities;
  another agent's output cannot grant them.

### Initial executable backend (development candidate)

The user approved an existing open model as a starting point: SmolLM2-135M-Instruct at
revision `83212e1e2b3cfd6958f3707877bb878945dea8ee` (Apache-2.0). The explicit guest-only
provisioner in `workers/volparossa-ml/` verifies every model asset and all 38 CPU Python
wheels against exact sizes/SHA-256 pins. It preserves original license/model-card bytes and
does not install on the development host or fetch dependencies at worker runtime.

`volparossa compute run` is preview-only unless `--execute` is supplied. The current CLI
supervises one real Python CPU worker in mandatory Bubblewrap network/PID/IPC/mount
isolation, exposing only the installed runtime, selected public dataset, pinned model and
new private output. The fixed worker performs inference or rank-4 LoRA training, compares
actual base/adapter tensors, saves safetensors, loads a fresh base plus saved adapter and
evaluates again. Rust enforces the wall-clock deadline, bounded protocol, resource-pressure
cancellation and external artifact hashes. There is no unsandboxed fallback, private-input
training, automatic cache training or automatic policy activation yet. Explicit public peer
job execution has the separate source-bound checkpoint below.

The initial resource boundary includes two CPU threads maximum, idle CPU/IO priority,
per-process address-space/CPU-time/file-size limits, bounded scratch space, sampled aggregate
RSS/output cancellation and an owner-cancellation input. Sampled RSS is **not** a hard cgroup
memory cap, and this foreground CLI does not detect all interactive activity or guarantee
physical-device safety. Actual model execution and sandbox observations now pass the source-bound
distinct-node smoke below: eight CPU optimizer updates change 230,400 LoRA parameters,
the original base remains unchanged, and a fresh base/adapter reload is evaluated.
B01 still needs broader interactive/physical-device evidence; real CPU-pressure pause/resume now
passes below. Improved answer quality, distributed
training and the full brain remain separate work. A small development model is not sufficient evidence for reliable
legal or content-policy judgments.

Owner-priority control adds `--spare-capacity` to `compute run` and `compute train-cycle`;
`compute serve` uses the same mechanism by default. Fixed, sequenced private-pipe commands
pause and resume at model/optimizer checkpoints, with acknowledgements from the execution
thread. CPU `some avg10 >= 20` or I/O `some avg10 >= 10` pauses; five seconds of continuously
sampled quiet permits resumption. Unknown pressure cannot authorize work; unknown or less than
512 MiB available memory across the host and unified-cgroup parent limits cancels and reaps it.
Existing RSS/output limits and the original wall-clock deadline continue while paused. The
broker advertises no free slot under observed pressure. These are coarse capacity observations,
not universal owner-activity detection or a hard cgroup reservation. Native operations are not
preempted mid-call; unacknowledged commands have a bounded timeout. Standard-library worker
process/pipe and focused Rust tests pass. The [actual owner-priority run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34876248467)
passes on exact source `d12768e31c0351e15416f05a8b986905367cab66`, including raw verification:
eight disposable-guest contenders produce CPU pressure; the same model worker acknowledges
pause/resume at step zero, uses zero CPU ticks in a measured 1.607-second paused interval,
then finishes eight updates within its original deadline. Total acknowledged pause is 8.599
seconds. All contenders/worker are reaped, temporary roots are removed and original guest-root
hashes match. This measures CPU-pressure handling, not all owner activity, owner-triggered
cancellation, battery/thermal behavior or the entire B01 criterion. Exact artifact/checker/hash
details are retained in [implementation status](IMPLEMENTATION_STATUS.md).

The device-priority candidate additionally reads exposed Linux system-battery and thermal
sysfs data, caching observations for at most one second. Battery charge at or below 20%
pauses ML work; at or below 5% cancels it, including while charging/on AC. Thermal zones pause
at 80°C and cancel at 90°C, or earlier when a lower passive/hot/critical trip minus a 5°C
margin applies. The [Linux inactive-trip placeholder](https://github.com/torvalds/linux/blob/v6.12/drivers/thermal/thermal_core.c)
is ignored as a limit, not treated as a temperature measurement; the software 80°C/90°C limits still apply. Malformed
or unreadable temperatures/trips remain unknown. Present but invalid observations pause work; `not_exposed` is
explicitly reported and does not prove absent hardware or safe temperatures. Critical observed
reserves still cancel when another observation is unknown. The train-loop's worker admission,
peer executors and explicitly enabled `--spare-capacity` jobs use this budget; seed imports
and update publication are not controlled by this ML device-budget gate.
`volparossa compute capacity` reads the same observations without changing device settings,
running a model or contacting the network. It is an admission hint, not a reservation or a
logind/interactive-activity detector. All 68 focused CLI compute tests and strict CLI Clippy
pass; physical battery/thermal behavior is not yet demonstrated.

The separate `agent-owner-cancel` guest fixture waits for real training, sends owner-UID
SIGINT only to the exact CLI through its pidfd, and requires CLI reaping and all observed
descendants ended within five seconds. It expects `compute_owner_busy`, not a completed
checkpoint, and checks the unchanged on-disk base, released runtime lock and guest cleanup.
The [actual owner-cancellation proof on `43dee7ed`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34893645697)
passes exact-source/raw-bundle verification. The CLI is reaped 3.242 ms after SIGINT and all
four observed processes end within 59.420 ms, without fallback signals. The base remains
unchanged, the runtime lock is free and cleanup leaves no owned objects. This is one measured
disposable-guest result, not a universal latency guarantee or completed B01.

### Cache-backed adapter candidate

The next implementation connects the worker to ordinary signed native content:

1. Publish the explicit public training JSON with content type
   `application/vnd.volparossa.agent-dataset.v1+json` using `content publish`.
2. `content agent pack --directory JOB/adapter --training-report JOB/report.json
   --dataset-manifest DATASET.manifest --publisher-key KEY --output ADAPTER.bundle`
   binds the exact three files and the job's dataset hash to the verified dataset manifest.
   Publish the resulting bundle as `application/vnd.volparossa.adapter.v1`.
3. `content agent fetch --publisher-key KEY --name ADAPTER_NAME --dataset-name DATASET_NAME
   --cache AGENT_CACHE --output NEW_PRIVATE_DIRECTORY` retrieves both objects through the
   existing protected peer path, verifies their original publisher and exact dataset link,
   and exports `adapter/`, `dataset.json` and `provenance.json`. Both publications must have
   the explicitly trusted publisher. A changed dataset revision is refused, not silently
   substituted for the one used to train the adapter.
4. An explicit `compute run --adapter-root .../adapter --dataset .../dataset.json` can use
   that adapter for inference or continued training. The fixed worker checks all 120 FP32
   tensors, exact shapes, finite values, fixed LoRA configuration and base identity before
   applying them. Peer-provided JSON never supplies runtime classes, scripts or operators.

All paths above are examples; supply absolute paths/private output parents and the normal
compute runtime/model/output arguments. `--execute` is required for computation; fetching
does not activate an adapter. `--cache-only --reuse-cache` is an explicit offline option,
not the default. Five focused Pack/CLI tests, four codec/native-chunk tests and eleven worker
protocol/adapter-validation tests pass locally. Separately, the
[`agent-artifact` guest run 34861750881](https://github.com/VOLPAROSSA/volparossa/actions/runs/34861750881)
on exact source `38814d30221c11ff73ef688f7a430c8b26fec3fe` now proves a live-model/two-node pass.
It trains/publishes in one producer's actual namespace,
restarts its durable contribution store after removing trainer files/key/cache, and requires
a different Client to fetch both objects over protected MPTCP and execute the received adapter.
The observer binds both jobs to distinct node service processes/namespaces and checks the
actual read-only input inodes. The fixture deliberately shares a pre-provisioned read-only
base/runtime; it does not prove base-model distribution. R4's eight optimizer updates are
followed by its durable-cache restart, a distinct Client's protected retrieval of 943,733 adapter
bytes and 1,005 dataset bytes with zero origin bytes, and actual use of the same 230,400 trained
parameters through read-only received inodes. Cache-only reopening after provider stop,
complete private/network cleanup and unchanged original guest-state hashes also pass.
The exact-source checker independently reconstructs the retained raw evidence; artifact and
hash details are recorded in [implementation status](IMPLEMENTATION_STATUS.md#current-candidate-functional-integration-in-progress).
This completes B02's explicit transfer/reuse scope, not automatic model activation or improved
answer quality. Native peer fetch
does not yet implement general external-corpus ingestion or bias-aware source selection.

### Explicit cache-backed training cycle

`compute train-cycle --publisher-key KEY --dataset-name NAME --dataset-manifest-id SHA256
--cache AGENT_CACHE --reuse-cache --runtime-root VENV --model-root MODEL
--adapter-root IMPORTED/adapter --output NEW_PRIVATE_CYCLE --steps 8 --execute`
joins source retrieval, actual local training and adapter packaging without separate manual
file-copy steps. Use absolute paths and pre-provisioned runtime/model directories; the adapter
and exact manifest pin are optional. Without `--execute`, it only prints the selected plan.

The operator chooses the publisher and dataset name before cache lookup. The optional exact
manifest pin, revision floor, fixed dataset type and 1-MiB object bound are checked by the agent
before peer-body retrieval, and again by the consuming CLI. An explicitly preferred complete,
unexpired cache object needs no route or provider; a miss retains the same publisher/name and
uses the normal protected retrieval path. This is not a globally newest-version claim, an
arbitrary-origin download, or permission to substitute another popular cached source. Source
signatures establish provenance, not legal/training-rights or model-quality guarantees.

The cycle records its selection before fetching and retains the original signed dataset,
source receipt, supervised training report and `adapter.bundle` in a new private directory.
An optional previously imported adapter is used as the actual warmstart; it is not silently
selected from cache. Training uses the existing isolated fixed worker, at most two CPU threads,
1–64 optimizer steps and at most 600 seconds, further bounded by source expiry. Interruption
cancels and awaits worker cleanup; incomplete files are retained rather than reported complete.
Publish the bundle separately with the normal content command. There is no automatic adapter
activation, source discovery, retraining loop, distributed gradient aggregation or policy change.
The [actual `agent-train-cycle` run on `d12768e3`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34876251732)
passes, including complete exact-source reconstruction from original raw evidence. A distinct
Client fetches 943,733 adapter bytes and 1,005 dataset bytes through protected paths. After
both providers stop, it performs eight warmstart updates using that cached dataset and the
exact received read-only adapter; all 230,400 adapter parameters remain bound to the original
dataset and the parameter hash changes, while the base stays unchanged. It produces a new
local bundle without publishing or activating it. The real control-owner change from R0 to R1
is rebound to its fresh exact routes and passes. Six captures / 28 interface rows / 10,515
frames have zero drops or forbidden tuples, both selected relay paths carry data, and cleanup
leaves zero owned objects with matching original guest-root hashes. The earlier `0d756a64`
fixture failure remains historical failure, not a retrospectively passing run. B05 remains open:
this is an explicitly chosen cycle, not autonomous training, defended aggregation or general
source discovery. Full source/artifact/hash details are in [implementation status](IMPLEMENTATION_STATUS.md).

### Continuous public training candidate

`compute train-loop` connects the existing real cycle executor to an owner-enabled persistent
coordinator. The plan is a version-1 JSON object with a `sources` array; each entry contains
`publisher_key`, `name`, and optionally `min_revision` and an exact `manifest_id`. These are
explicitly eligible public sources, not browsing history or a scan of whatever is cached.
Round-robin selection and retry timing operate on that plan before cache lookup. Missing bytes
are requested for the same selected source; this avoids cache availability deciding the corpus,
but does not claim representative, unbiased or automatically discovered training data.

```sh
volparossa compute train-loop --plan /OWNER/public-sources.json \
  --directory /OWNER/training-loop --cache /AGENT/existing-cache \
  --runtime-root /OWNER/existing-runtime --model-root /OWNER/existing-model \
  --steps 8 --execute
```

These are illustrative absolute paths: the private parent, pinned runtime/model and native
agent cache must already exist. Nothing is installed or downloaded as executable code by this
command. Without `--execute`, it only previews enrollment. Omit `--max-cycles` to keep watching
until SIGINT/SIGTERM; that option limits new attempts in this invocation, not lifetime progress.
`--resume` reopens the exact enrolled directory and continues from durable state. Subsequent
cycles warmstart from the last completed local adapter. By default, a source must provide a
newer revision after success; `--repeat-sources` explicitly permits training on unchanged data.

An optional `--seed FILE` selects an initial protected peer import by `publisher_key`,
`dataset_publisher_key`, `name`, `dataset_name`, and optional adapter `min_revision`. The two
publisher keys are independently trusted; the dataset must match the exact original identity
inside the adapter bundle. Alternatively, `--adapter-root` selects an existing local adapter.
The coordinator cannot silently replace either source with an arbitrary peer's model.

Automatic sharing is separately enabled with `--publish-name`, `--publication-key`, the existing
encrypted `--identity`, private `--passphrase-file`, and an existing owner `--publish-cache`.
Each completed bundle is signed once, never beyond its dataset's original expiry. Failed
handoffs retry that exact manifest through `content contribute`; they do not re-sign it or
renew its lease. Completed transfer receipts can be reconciled after a restart. This contributes
the adapter, not automatically its source dataset: a receiver still needs the independently
trusted dataset available from an authorized provider. CLI `content agent fetch` also
accepts `--dataset-publisher-key` for this case; omission preserves same-publisher behavior.

The overall watcher has no preset end time, but runs one bounded, spare-capacity worker at a
time. Existing source expiry, CPU/thread, memory, per-worker deadline and cache limits remain.
It retains at most eight cycle directories; the current warmstart and pending publications
are never pruned to make room, so a full pending queue pauses further training. Interrupted
workers are not marked complete. An initial peer import interrupted between atomic output
publication and its state checkpoint is retained and refused on resume, not silently trusted.

The separate [`agent-train-loop` proof on `bcc1df52`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34887897332)
passes with two genuine eight-update cycles, exact signed automatic contributions and another
Client's protected import and real inference using the second adapter. Original raw measurements
reconstruct the same report; cleanup leaves no owned objects and original guest-host state is
unchanged. PR #123 integrated this milestone into `main`. This is not general task planning,
model-quality improvement, private training, defended
gradient/model aggregation, automatic peer-job activation or completed B05.

### Source-heldout successor selection

New train-loop enrollment fixes `quality_policy: source-heldout-loss-v1`. A technically complete
training cycle is now a candidate, not automatically the next warmstart. The worker already
measures token-weighted held-out loss after applying the predecessor and before training,
then after training and after a fresh checkpoint reload. Only a finite reloaded-candidate loss
strictly below the predecessor loss minus `1e-6`, with matching positive target-token counts
and reload consistency, approves promotion and optional automatic publication.

Each cycle retains `evaluation.json` with exact source, report, predecessor and adapter
bindings. Recovery and publication recheck that decision against the immutable cycle snapshot.
Rejected candidates keep their real output, do not replace the previous warmstart and are
eligible for bounded local cleanup. Source revision tracking still advances after a measured
rejection, so the same revision is not silently trained forever. The loop reports technical
completions, promotions and rejections separately.

This changes coordinator state to version 2 and adds the enrolled policy. Existing version-1
loop directories are not silently migrated or relabelled: keep their results, and start a new
directory with an explicitly selected compatible adapter if further training is wanted.
The current source supplies both training and held-out examples; within-source disjointness
does not establish an independently selected benchmark or exclude cross-round contamination.
This is a scoped measured promotion rule, not evidence of general intelligence, no forgetting,
globally monotone improvement or robust peer evaluation. Independent evaluation/selection and
specialist retention remain required work. The [actual proof on `405e67e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34896078997)
passes its exact-source checker and raw reconstruction: two genuine eight-update cycles,
loss `1.244269 → 0.615178 → 0.345725` on four target tokens, both approved and contributed,
then actual protected retrieval and inference by another Client. That live run took no rejection
branch. Cleanup left zero owned objects and unchanged guest-host state; this is still only the
small, same-source selection proof described above.

### Explicit second-source validation candidate

Add `--validation-source /absolute/path/validation-source.json` to a new loop's normal command.
This private JSON has the same `publisher_key`, `name`, optional `min_revision` and
`manifest_id` fields as a source-plan row, but **requires an exact manifest ID**. Select it
independently of cache availability, with a different publisher/name pair from every training
source. It must be a signed public v1 dataset with `train: []`, 1–8 held-out rows and 1–4
inference rows. The runtime verifies its signature and bytes, uses the cache when available,
and retrieves that exact source over protected routes on a miss. It never substitutes a
more convenient cached dataset.

Enrollment fixes `source-and-second-source-loss-v1` and pins the retrieved source before any
loop training. Every newly fetched training source is checked for normalized-question overlap
with the validation rows before model work. Each completed training cycle then runs two
sequential, isolated `infer` jobs: the retained predecessor (or initial adapter/base) and the
new candidate, on identical second-source bytes, without gradient updates. Promotion requires
the original source-heldout gate **and** second-source loss improvement greater than `1e-6`.
Both jobs retain the ordinary owner priority, resource limits and source-expiry deadlines.

The `evaluating` phase saves the finished training checkpoint before comparison. Validated
completed inference stages and their original deadlines are reused on resume without training
the candidate again. A partial inference output lacking its supervisor's durable result is
retained as an explicit interrupted-stage error, not silently accepted or overwritten. Completed
cycle snapshots bind all source files, both actual reports and the final decision. Rejection
still preserves the previous approved adapter and remains eligible for bounded reclamation.

Repeatedly selecting on this set makes it a validation/selection set, not a fresh independent
test benchmark. Question matching does not detect semantic overlap or prove that a pretrained
base/imported seed never saw the content. It does not establish general intelligence or global
quality improvement. The upgraded disposable training-loop proof is pending; B05 stays open.

## Owner-first resource allocation

Training and opportunistic model redistribution use only the node's available contribution
budget, after local interactive work and the agreed network duties. Enforce memory, CPU time,
GPU memory/time where available, storage/free-space, disk IO, network, concurrency and job
deadlines in the runtime, not merely by asking an AI to be considerate. Pause/checkpoint or
cancel background jobs under owner activity, pressure, heat or battery constraints. Sharing
models must share the existing owner budget, not create another independently full bandwidth
allowance. Unknown available capacity is not permission to saturate the device.

Assignment considers measured completion rate, latency, data/model locality, available memory,
device capability and shared bottlenecks. Model-transfer cost can exceed the cost of a local
job. Preserve local-first work when it is faster or required by privacy. Expiring leases,
idempotent task IDs and bounded re-assignment handle disconnecting peers; validation/repair
work must itself have a budget. Zero disturbance or additive speedup cannot be guaranteed
without measurement on representative devices.

Task size is not the same as a worker lease: large or long-running workflows should be split,
checkpointed and resumed across multiple bounded steps. No final whole-workflow size or duration
limit is implied by the first worker's four inference rows and 600-second lease. Per-device
resource limits remain necessary. General workflow continuation and checkpoint scheduling are
not supplied by the initial worker. The explicit multi-package coordinator below is a first
continuation step, not general task decomposition or unlimited execution permission.

## Current public peer-job candidate

The development CLI now has an explicit `compute serve` broker and `compute peer
attach/capabilities/submit/poll/cancel/distribute/resume/workflow/task` commands. The broker must already have the
pinned runtime/model (and optional verified adapter), uses one isolated worker slot, and is
off until explicitly executed. The agent attaches only a protected same-UID socket and an
explicit allowlist of dataset publishers. It does not launch Python inside the hardened
network-agent service or accept remote commands, model downloads or filesystem paths.

Peer requests use short challenge-bound signed exchanges inside the existing authenticated
provider TLS over protected MPTCP/WireGuard, never a direct Client-to-Exit or provider dial.
Public dataset signatures, original object/chunk hashes, expiry and exact derived row bytes
are checked before export and again by the receiver. A fresh identity signature alone is not
permission to submit an arbitrary source. Polling and cancellation require the same authenticated
owner and entire original job binding. Expiry prevents new admission, but not owner cancellation
of a worker still being reaped.

`compute peer distribute` currently divides two through four independent public inference
questions across explicitly selected compatible peers, sends the tasks concurrently, and joins
results in their original row order. It saves immutable handles before submission, retains
partial/ambiguous failures, checks model/input/result bindings, and supports explicit follow-up
poll/cancel. The scoped two-executor raw-evidence proof below now passes; this is not a proven full B03
checkpoint. Automatic peer selection/reassignment, general multi-step
continuation, distributed optimizer/model-layer execution, confidential private tasks and
correctness of a remote model's answers remain unimplemented or unproved. A signature establishes
who reported a result, not whether the result is true.

`compute peer resume` now explicitly reopens supplied task handles against the same original
signed public source, reconciles completed/running/missing/failed observations, and can retry
unfinished parts once on independently supplied compatible peers. An ambiguous, unexpired lease
is not reassigned; an expired unreachable lease stays labelled unconfirmed, not observed stopped.
Original IDs/deadlines remain unchanged and replacement attempts get distinct saved handles.
Results report which rows were requested, including when only part of the original dataset was
resumed. This is bounded explicit recovery, not an automatic general workflow scheduler or an
exactly-once execution guarantee. Its source/handle tests and the explicit live worker-loss/recovery
checkpoint below pass. Terminal broker receipts receive a nonrenewable 60-second observation
grace after observed completion, without extending any execution lease or the eight-record cap.

The `agent-jobs` disposable guest runner exercises two independent CPU workers on separate nodes,
with separate runtime-lock inodes and process-overlap observation, signed disjoint public input
rows, protected network traffic and source-bound results. Only the verified base model bytes are
shared in that fixture. Its first run stopped before model execution during capability lookup;
an already closed initial route socket is now replaced before application TLS. The next
[run on `2ba9631e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34869250045)
completed both real model jobs and returned their two disjoint results, but failed the live
overlap/isolation check because its process detector omitted children spawned by other threads.
That detector and the analogous runtime resource accounting now inspect every bounded thread;
local real-process regressions pass. The subsequent
[run on `4e22b7ce`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34871353888)
retained the simultaneous actual-worker observations, both complete model receipts, protected
path captures and full cleanup. It failed only because its final checker expected a nonexistent
`manifest_id` field from offline publication. Checker correction `3f5ee282` instead derives the
ID from the retained original signed bytes, checks their recorded hash/length and publisher/expiry,
and reconstructs the complete original raw evidence successfully. No missing observations were
invented; the historical workflow remains failed. This proves the scoped two-public-job execution,
not general task decomposition, live reassignment, private offload or improved answer quality.
Cleanup and unchanged guest state passed even in the failed runs. The separate
`agent-jobs-loss` scenario additionally terminates one exact guest-owned Python worker via pidfd,
requires terminal original receipts, and resumes only its failed rows on the idle surviving
peer. Its checker requires a genuinely new worker and preserved original successful output;
[its run on `0d756a64`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34873353570)
now passes with exact-source raw reconstruction equal to the original reports: R4's actual
worker is killed, the concurrent R5 result survives unchanged, and only R4's failed row is
executed once on a new R5 worker. Both selected two-leg WireGuard paths carry data; all six
captures have zero drops/unexpected outer packets. Original handles/deadlines remain intact,
cleanup leaves zero owned objects and guest-state hashes match. This proves bounded explicit
public-job recovery, not automatic general planning or private computation; B03 remains open.

### Explicit multi-package workflows

`compute peer workflow --plan PLAN.json --directory NEW_PRIVATE_DIRECTORY --provider-key KEY_A
--provider-key KEY_B --max-batches 1 --max-seconds 600 --execute` enrolls a finite version-1 plan:

```json
{"version":1,"packages":[{"dataset":"/absolute/public-dataset.json","dataset_manifest":"/absolute/public-dataset.pb","publisher_key":"INDEPENDENTLY_TRUSTED_PUBLISHER_KEY_HEX"}]}
```

Without `--execute`, enrollment only previews and performs no network I/O. The current plan
accepts 1–32 packages, each containing 2–4 independent public inference rows; these are initial
enrollment bounds, not a promise of arbitrary natural-language task planning. A private directory
retains exact original source bytes, signed manifests, peer selection and per-attempt handles.
`compute peer workflow --directory EXISTING_PRIVATE_DIRECTORY --resume --max-batches 1 --execute`
continues that same enrollment. Each invocation advances only its explicitly bounded number of
ordinary distribute/reconcile rounds; `Busy` or ambiguous work stays pending instead of an
unbounded retry loop. Each new executor still receives its own bounded lease, so the complete
sequence can span longer than 600 seconds without extending an old lease.

Previously completed parts are reconstructed from full input/model/handle-bound receipts saved
after authenticated RPC validation, not from an unchecked `complete` flag. These private local
receipt files are not independently provider-signed portable attestations and do not prove
answer quality. Historical result verification does not renew a source: new work must still
pass current source-expiry and authorization checks. Source selection remains explicit and
independent of cache presence; no automatic corpus choice, model download, confidential offload,
cross-model planning or distributed optimizer is implied. Live multi-package and worker-loss
proofs remain separate from the local coordinator tests.

Both `compute peer submit` and `distribute` preview without network I/O unless `--execute` is
present. An explicit submit consumes a preselected signed dataset, whether obtained from an
eligible origin, a peer or cache. These commands do not automatically choose a training corpus.

### Source-bound public user tasks

`compute peer task` adds a requester instruction to the original public source, rather than
requiring the publisher to have authored that exact question. It selects the source by trusted
publisher/name and optional minimum revision/exact manifest ID, independently of cache inventory.
Eligible cached bytes accelerate retrieval; a miss requests the same source over the protected
network. Peers still require their existing publisher allowlist and explicitly advertise
`task_derivation_v1`; unsupported peers refuse the new task.

```sh
volparossa --control-socket /absolute/agent.sock compute peer task \
  --publisher-key TRUSTED_DATASET_PUBLISHER_HEX --dataset-name public-notes \
  --cache /absolute/agent-cache --reuse-cache \
  --provider-key WORKER_A_HEX --provider-key WORKER_B_HEX \
  --public-question 'What does this public context say about conserving capacity?' \
  --directory /absolute/private-parent/task-001 --execute

volparossa --control-socket /absolute/agent.sock compute peer task \
  --directory /absolute/private-parent/task-001 --resume --execute
```

Omit `--execute` for a no-network/no-output-creation preview. Omit `--public-question` for
the fixed instruction `Summarize the provided public context.` The question is explicitly public
and visible to the workers; never put private text in it. Its exact bytes are bound separately
in the signed requester job, never attributed to the original dataset publisher. Original
context/source bytes remain unchanged and are verified at both agent boundaries.

The current adapter accepts one existing signed public-dataset object with two to four inference
contexts and two to four explicitly selected peers. It does not yet split arbitrary documents;
each worker retains the existing 192-token prompt check without silent truncation. The user
question allows at most 512 UTF-8 bytes. These are current input/worker limits, not a promise that
the final whole-task interface will always have these limits.

`result.json` contains ordered per-context answers with original manifest/context hashes and
the responsible peer, job and validated report hash. It is not a further neural synthesis or
proof that model answers are correct. Exact task/source/peer enrollment and completed local
receipts survive resume, while partial work remains visibly incomplete. Those receipts are
authenticated local observations, not independently portable execution attestations. The
source signature does not authorize relabelling derived answers as publisher-authored content.
The [disposable `agent-public-task` run on `42761c28`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34889536964)
passes exact-source report checks and reconstruction from its original raw evidence. It
retrieves a 721-byte signed source over the protected network, executes two real isolated
peer workers, then stops both brokers and the route before a zero-round resume. All 15 retained
file hashes/inodes and ordered answers remain unchanged; cleanup leaves no owned objects.
The separate historical Quality `unreadable_literal` failure remains a failure, with its
source correction included in `974c6555`. This scoped result does not complete B03.

### Public document tasks

The `compute peer document` candidate splits a user-selected public UTF-8 document, rather
than requiring pre-authored inference rows. The existing pinned tokenizer runs in the isolated
worker without loading model weights, using the exact chat template used by inference.
Every segment fits the full 192-token prompt budget and preserves contiguous original UTF-8
byte ranges; no text is silently truncated. Each package has up to four segments and its own
resumable workflow, so a whole document is not limited to one worker lease or one workflow's
32-package plan. A final singleton uses one worker, not an invented second task.

```sh
volparossa --control-socket /absolute/agent.sock compute peer document \
  --input /absolute/public-document.txt --public-content --license CC-BY-4.0 \
  --public-question 'What does this section explain?' \
  --runtime-root /absolute/existing-runtime --model-root /absolute/existing-model \
  --identity /absolute/existing-identity --passphrase-file /absolute/private-passphrase \
  --publisher-key OWN_PUBLISHER_HEX \
  --provider-key WORKER_A_HEX --provider-key WORKER_B_HEX \
  --directory /absolute/private-parent/document-001 --max-batches 1 --execute

volparossa --control-socket /absolute/agent.sock compute peer document \
  --directory /absolute/private-parent/document-001 --resume --max-batches 32 --execute
```

The paths above are illustrative. Provisioning is explicit; this command installs/downloads
no runtime, tokenizer or model. The input must already be public and you must be authorized
to publish it under the selected license (GPL-3.0-only, CC0-1.0, CC-BY-4.0 or CC-BY-SA-4.0).
`--public-content` explicitly authorizes disclosing both the entire source and the question;
there is no automatic browsing/cache ingestion. Peers must independently trust the publisher
and advertise `document_inference_v2` as well as requester-task support.

The coordinator compares every excerpt against the actual original bytes before signing a
v2 inference-only package. Packages carry the same publisher's signed original text manifest.
That signature authenticates the publisher's excerpt assertion; a remote reference alone is
not a cryptographic proof of byte equality without the original. Original text and packages
are stored in a local native content cache, not automatically contributed as network replicas.
This owner-input path does not claim to have fetched the original source from the network.
It contains no invented training examples, held-out answers or repository revision.

Current enrollment accepts at most 1 MiB of input, 16,384 segments and two to four explicit
peers. Individual prompts/answers, resource budgets and worker leases remain bounded.
`--max-batches` limits new rounds per invocation (1–32), not completed lifetime progress.
`result.json` preserves ordered range answers and exact source/context/job/provider/report
identities; it is not neural synthesis, answer-quality proof or an independently portable
execution attestation. An unfinished invocation returns a nonzero status but retains complete
receipts. Resume never reassigns completed work or silently renews expired source permissions.
The new `agent-public-document` disposable scenario targets real tokenizer splitting,
multi-package execution and receipt reuse after peer/route shutdown. Its [first run on
`974c6555`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34891322172) stopped before
tokenizer/model execution because the Client UID could not traverse the guest source tree.
The `4421b1a6` correction installs only the public helper and a read-only public README copy
in the guest workspace, preserving source-tree restrictions. Local checks pass; the corrected
[live proof](https://github.com/VOLPAROSSA/volparossa/actions/runs/34893180542) is pending.
The original failed run has complete cleanup and unchanged guest state.
Full B03 and confidential tasks remain open.

## Private tasks and training data

Encrypted transport does not hide plaintext from the device performing ordinary inference.
Federated learning alone also does not prevent recovery of training data from updates or
trained models; [NIST describes both attacks](https://www.nist.gov/blogs/cybersecurity-insights/privacy-attacks-federated-learning/).
Therefore raw private prompts, documents, outputs and per-user learning updates are not public
cache objects or default training data. Initial distributed experiments use explicit public,
licensed/authorized inputs; privately trained artifacts remain private unless an implemented
and evaluated privacy mechanism authorizes release.

Private distributed execution remains required work, not something to relabel as private
because a task is split among peers. Define the worker-operator, collusion, traffic and model
extraction threat model; evaluate an actual confidential-computation approach and its cost.
Where that protection is unavailable, keep sensitive execution local or refuse remote execution
with an explicit reason. Do not silently send it to an ordinary untrusted peer.

Secure aggregation and differential privacy are candidate building blocks, not installed
features or blanket guarantees. The [Bonawitz et al. secure-aggregation protocol](https://research.google/pubs/practical-secure-aggregation-for-privacy-preserving-machine-learning/)
protects aggregation under stated assumptions and uses a server role; it is not by itself a
decentralized inference engine. Any adoption needs a compatible decentralized trust model and
explicit privacy accounting. Public task results may be shared only when the job permits it;
private results remain recipient-protected and expire independently of public models.

## Fully automatic whitelist/blacklist decisions

The existing [whitelist](WHITELIST.md) already enforces threshold-signed **destination/port**
rules. It does not classify all content behind an allowed hostname. Native object decisions,
individual HTTPS resources, domain reachability and worker/tool permissions require separate
typed scopes; allowing a domain is not approval of every page it serves. Relays and exits do
not gain general HTTPS plaintext access for this extension. No interception CA or browsing
catalogue is introduced.

The proposed automatic pipeline is:

`scoped proposal -> independent evaluations -> conflict resolution -> signed decision -> activation`

Each decision binds the exact subject/version, principle-policy version, evidence scope,
assessment/model versions, validity and authorized decision epoch. Conflicting assessments
remain visible to the resolver; agreement is not established by counting duplicate agents.
Unknown or contested assessments require an explicit outcome and bounded re-evaluation rather
than invented certainty. Exact precedence between whitelist and blacklist, reconsideration and
the contextual categories above still need specification. Fully automatic re-evaluation remains
the target; a mandatory human approval gate is not being substituted.

Automated decision participants need an explicit membership/quorum/rotation and anti-capture
protocol. Existing operator/network diversity is useful evidence but does not prove Sybil
resistance or independent judgment. A majority of arbitrary DHT identities cannot replace
trusted signing authority. A common verified epoch and split-brain/partition behavior must be
defined before global automatic activation can work. The current trust anchors and fail-closed
policy stay unchanged until that migration is implemented; no single AI holds a network-wide
master signing key and no mandatory human approval is substituted for the requested target.
The activation chain now includes a durable version/hash floor after threshold verification;
separate-process tests prove restart retention, rollback rejection and equal-version conflict
rejection. This guards the existing configured authority scope. It does not define decentralized
membership, authorize key rotation, judge content or complete automatic governance.

## Mutual checking, quarantine and repair

Bind observations to specific agent/model artifacts, task contracts and observed failures.
Use independently checked outcomes, regression/poisoning checks and diverse assessors; copied
models or coordinated peers can share the same error. Disagreement alone is not proof of a
rogue agent. [NIST's adversarial-ML taxonomy](https://doi.org/10.6028/NIST.AI.100-2e2025)
documents model poisoning and limitations of mitigations.

Local workers can automatically quarantine an artifact that violates its runtime contract,
stop assigning it work, revoke its scoped lease and fall back to a known accepted version.
Network-wide quarantine/replacement follows the automatic decision protocol, with bounded
evidence, expiry and re-evaluation. A peer cannot erase another user's files or repair their
host; removal means withdrawing execution/serving authority and deleting only locally owned
artifacts under the owner's storage policy. Network-wide erasure of every copy is not promised.
Validated formats still require resource isolation: even a syntactically valid model can
consume excessive resources, as the [ONNX Runtime model-validation guidance](https://onnxruntime.ai/docs/)
explicitly notes. The pinned development backend above is implemented; this is not approval
to execute arbitrary peer-selected models or dependencies.

## Executable sequence and completion evidence

Finish the current public-custody route integration while specifying how the agreed legal
baseline and contextual category boundaries become versioned rules. Then
build larger connected slices, without claiming these unchecked requirements are implemented:

- [ ] B01: isolated on-device execution and genuine bounded training; measured owner-priority
  pause/resume/cancellation, not a stub model or an unconstrained background process.
  Actual bounded CPU training and kernel-observed isolation pass on `38814d30`; real CPU-pressure
  pause/resume passes on `d12768e3`. Device-budget code and the manual-cancellation fixture
  pass local checks; measured owner cancellation passes on `43dee7ed`. Physical battery/thermal and broader
  interactive-activity evidence remain incomplete.
- [x] B02: transfer an original compatible trained artifact over the real protected content
  network, validate it on another node and execute it there; restart/custody retains validity.
  [Run 34861750881](https://github.com/VOLPAROSSA/volparossa/actions/runs/34861750881), exact source
  `38814d30221c11ff73ef688f7a430c8b26fec3fe`, proves this explicit public-adapter scope with a
  pre-provisioned common base/runtime; automatic activation/distributed training are not included.
- [ ] B03: decompose and distribute useful user jobs across independent nodes, collect verified
  results and recover from worker loss with bounded duplication and actual resource accounting.
- [ ] B04: demonstrate private input, training-update and result handling against the stated
  worker/collusion threat model; encrypted transport or local-only inference is not the complete
  requested private distributed-computation result.
- [ ] B05: autonomously train/update cooperating models with compatible update validation and
  defended aggregation, without private-cache admission or unbounded device/network demand.
- [ ] B06: fully automatic scoped policy judgments, independent conflict resolution, authorized
  common-policy activation and partition/rollback behavior; no human gate as the target design.
- [ ] B07: detect an injected bad update/worker, quarantine it without a cascade of false bans,
  recover useful work and restore an accepted artifact under the same contribution budgets.

These requirements add real remaining work. Existing A01--A15 and C01--C07 evidence alone does
not prove B checkpoints; B02 has its own exact-source run above. No new completion percentage
or delivery-time guarantee follows.
