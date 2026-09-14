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
training, automatic cache training, peer job execution or automatic policy activation yet.

The initial resource boundary includes two CPU threads maximum, idle CPU/IO priority,
per-process address-space/CPU-time/file-size limits, bounded scratch space, sampled aggregate
RSS/output cancellation and an owner-cancellation input. Sampled RSS is **not** a hard cgroup
memory cap, and this foreground CLI does not yet detect all interactive, thermal or battery
conditions. Actual model execution and sandbox observations must pass the disposable-guest
smoke before claiming B01; improved answer quality, distributed training and the full brain
remain separate work. A small development model is not sufficient evidence for reliable
legal or content-policy judgments.

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
protocol/adapter-validation tests pass locally. These are not a live-model or two-node pass;
the new `agent-artifact` guest scenario trains/publishes in one producer's actual namespace,
restarts its durable contribution store after removing trainer files/key/cache, and requires
a different Client to fetch both objects over protected MPTCP and execute the received adapter.
The observer binds both jobs to distinct node service processes/namespaces and checks the
actual read-only input inodes. The fixture deliberately shares a pre-provisioned read-only
base/runtime; it does not prove base-model distribution. This scenario is still awaiting a
passing live result. Native peer fetch
does not yet implement general external-corpus ingestion or bias-aware source selection.

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
explicitly notes. No inference backend or model dependency has been selected or added yet.

## Executable sequence and completion evidence

Finish the current public-custody route integration while specifying how the agreed legal
baseline and contextual category boundaries become versioned rules. Then
build larger connected slices, without claiming these unchecked requirements are implemented:

- [ ] B01: isolated on-device execution and genuine bounded training; measured owner-priority
  pause/resume/cancellation, not a stub model or an unconstrained background process.
- [ ] B02: transfer an original compatible trained artifact over the real protected content
  network, validate it on another node and execute it there; restart/custody retains validity.
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

These requirements add real remaining work. Existing A01--A15 and C01--C07 evidence does not
prove any B checkpoint, and no new completion percentage or delivery-time guarantee follows.
