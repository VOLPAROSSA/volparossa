# Weather Demo 0 — effort, consumption and uncertainty

Model counters, CI elapsed time and human engineering effort are different
measurements. None is a subscription invoice, quota conversion or bill estimate.

## Recorded usage projection

`scripts/weather-demo-0-usage.py` selects the implementation turn and both resumed
implementation turns as a union, deduplicates thread/files and cumulative snapshots,
and separates cached input, uncached input and output. The earlier readiness-audit
turn is excluded. Reasoning is already a subset of output and is not added again.

The retained `model-usage.json` is a **projection with incomplete counters**, not
exact task consumption. Missing fields in a selected delta or its baseline use
legacy zero defaults; derived uncached counts for those deltas are unconfirmed.
Gaps without intermediate snapshots can include unselected work. Missing records
can overcount or undercount; unlisted sessions and later work are unmeasured.
No defensible exact billing total or error bar can be inferred from these logs.

An intermediate six-thread projection, before final independent review and CI,
was approximately **194 million cached input, 5.28 million uncached input and
604 thousand output tokens**. The [retained snapshot](measurements/model-usage.json), taken after final media export
and before final packaging/upload, supersedes it: approximately **241 million
cached input, 5.81 million uncached input and 805 thousand output tokens**.
Later final-review/packaging/upload tokens are outside that snapshot. The
original planning range (5–25 million cached, 0.25–1.2 million uncached and
30–120 thousand output) was substantially optimistic relative to this recorded
projection. Repeated long-context coordination, diagnosis and review dominate
much of the cached input. Rework is included, not hidden as successful development.

| Thread suffix | Responsibility | Recorded routing |
| --- | --- | --- |
| `4131036e94d9` | Coordination, integration, evidence and presentation | Sol High |
| `0f3e43fc2e9e` | Recording implementation, difficult media/timing correction | Sol High |
| `84b14a5aa9bf` | Artifact inventory, provenance and CI support | Luna Medium |
| `794ca99cb7c2` | Source bundles, retained-media wrapper and presentation integration | Sol Medium |
| `f7b3f25f485d` | Independent technical and actual-pixel review | Sol High |
| `cc284ee99256` | Consequential timing/scope architecture decision | Astra Ultra |

The recording implementer's installed role was named `volparossa_reviewer`;
that label does not make its implementation independent review. The separate
reviewer supplies independence. The coordinating thread actually records Sol
High; it does not claim to be Astra. The separate active Astra project goal and
worktrees were untouched. A bounded Astra Ultra review addressed the media-clock
contract and visible scope without redesigning Core or the application.

## CI and necessary correction

The three full new Android/Core trials each passed their original real product,
installed-app, peer/cache and cleanup checks, then failed additional media gates:

| Run / attempt | Extra media outcome | Workflow elapsed |
| --- | --- | --- |
| `39864237681 / 1` | Opaque initial rejection; no media exported | 41m 55s |
| `39870500157 / 2` | Three-stream profile rejected | 36m 35s |
| `39998753810 / 1` | Host-wall duration proxy rejected; quarantine retained | 34m 53s |

These are approximately 113 minutes of completed workflow elapsed time, not
billed runner minutes. The first attempt of `39870500157` separately spent about
10m 55s on package-download failure before Android. The quota interruption was
elapsed calendar time, not engineering or CI work. [ci-wall-time.json](measurements/ci-wall-time.json) records
individual later probes/reviews; do not sum parallel job times as billed usage.

Necessary corrections included ffprobe's empty `programs` serialization,
Android's two Winscope timing tracks, an incompatible font-data guard, slow Ubuntu
mirror acquisition, a rejected synthetic metadata strategy, credential isolation
in inert CI tests and PNG-encoder time-base handling. Failed probes are retained
under `trials/`; synthetic probes establish tool behavior, never Android/Core
acceptance. Two early full trials could not retain pixels; dedicated quarantine
was then added so later failures preserved the original source-bound recording.
Additional scoped admission attempts rejected recursive ffprobe field selection,
format-inferred DATA durations and missing native DATA packets. Source analysis
proved FFmpeg deliberately discards all-zero-STTS DATA tracks; bounded MP4 sample
tables now bind their metadata independently. Later presentation diagnostics
preserved the successful timing checkpoint and identified a reintroduced font
provenance/tool-data guard; the already verified font-data check was reused.
These failures and corrections remain in `trials/`. The final scoped timing admission replaces the invalid host-wall coverage proxy
without altering the original delivery deadlines or failed workflow conclusion.

The retained-source review avoids another expensive Core/APK rebuild. Native
frame inspection run `40008276524` completed in about a minute; final admission
and video rendering are separate cheap hosted media operations.

## Remaining effort and model allocation

For this milestone, remaining work is only whatever the final manifest and release
gate identify; publication remains the user's decision. No further Core rewrite
or standalone packaging is implied. Before final rendering, the bounded remaining
review/render/package work was estimated at roughly 1–4 engineering hours,
0.5–5 million cached input, 30–200 thousand uncached input and 5–35 thousand output.
That remaining-stage range also proved optimistic after the additional native
format/parser and provenance corrections. It was a planning range with roughly
factor-two uncertainty, not a reliable bound; these figures are
not measured savings or a token commitment. New serializer or rendering failures
can add a CI cycle and further diagnosis.

Use Sol Medium for established wrappers and presentation glue; Sol High for native
format/debugging and independent review; Luna Medium for bounded inventories,
notices and evidence indexing; Astra Ultra for acceptance, architecture or trust
boundary decisions. Actual routing metadata must verify the assignment.

An installable technical preview still needs exact app/companion artifacts,
compatible Core packaging, installation/update/security acceptance and a supported
platform matrix. A standalone phone app additionally needs functioning Core on
that target, contribution/privacy enforcement and device evidence. These are
separate projects; this demonstration does not establish a reliable schedule or
model-token estimate for them. Renewed native input admission after Actions
artifact expiry is an explicit reproduction dependency, not a free cache hit.

The retained CI ledger contains 21 completed workflow executions/attempts,
approximately 151 minutes of summed elapsed time including the infrastructure-only
attempt. This is not billed runner time. The final media run succeeded; original
runtime/admission failures remain failures. The independent review thread projects
approximately 30.1 million cached input, 1.88 million uncached input and 71 thousand
output; its missing-baseline caveats still apply. CI execution itself consumes
runner time; model calls inspecting CI belong to their recorded thread counters.
No causal per-bug token split or controlled model-routing savings is established.
