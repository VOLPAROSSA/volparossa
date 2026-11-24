# Cooperative browser: real public peer execution

On 19 November 2026 the public ESR panel completed a two-peer answer and
cancelled a second live task. An independent observer saw all 21 first-task
workers and both cancellation-task workers finish. The full KVM trial failed
its route-continuity check. [Hosted trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434704508)
· [Original panel, execution, worker and route reports](development/evidence/browser-cooperative-44434704508)

The public browser integration has a separate socket and panel from private local
compute. `ask(question, context)` prefills the panel only. Sending requires a supported
content license, rights confirmation and explicit public-content consent. Public input
and signed execution receipts remain in the owner's private task directory until the
owner removes it; peer cancellation is not a global-erasure guarantee.

The disposable `agent-cooperative-browser` scenario joins three actual components:

1. Exact-pinned Gecko ESR 140.16.0 and browser source
   `326ce0f2de2b72ce2769e95ddb8b009d6266f2ae` drive the real public panel.
2. `compute public-serve` owns the signing identity and model/runtime configuration;
   the browser submits no paths, model code or signing keys.
3. Two real compatible peer workers execute signed public fragments and hierarchical
   synthesis over the existing protected WireGuard/MPTCP topology.

The service candidate also accepts operator-selected `--discover-peers` instead of
fixed provider keys. It reuses core discovery and eligibility checks before enrolling
each new task; the browser still supplies no providers or model configuration.
Selection stays within the operator's model profile and one mutually compatible
fingerprint. The validated retained enrollment determines the reported selected cohort;
actual executor keys remain separate. This does not yet implement automatic model
choice or cross-job answer continuation. The discovered-360M browser trial
recorded below used service discovery for its signed peer jobs.

An explicit operator `--refine-incomplete` setting authorizes bounded recovery
for token-limited public document leaves. It is retained with the original enrollment;
the browser cannot enable it or select new peers. Complete original answers are reused,
while each affected source range becomes two smaller, genuinely tokenized and signed
jobs in the same model/cohort. Every original answer and receipt remains unchanged.
The default remains one split level. Explicit `--refinement-levels 2..4` allows a
still-token-limited child to be split again, with a new intent bound to that child's
own immutable receipt and exact source range. Across all levels together the bound
remains sixteen split intents and thirty-two child jobs, sharing the existing
invocation round/time budget, original validity and cancellation. CLI `--follow` retains its
existing window semantics but grants at most one shared recovery window, not a new
window for every child.

The effective answer set may feed synthesis only after every terminal frontier leaf
shows EOS and covers the exact original range. Intermediate token-limited child
receipts remain unchanged and cannot enter synthesis themselves. A child that cannot
be repaired within the limits remains incomplete; the mechanism does not repeat the same terminal job, enlarge the model
limits or turn a partial answer into a complete one. Retained child jobs resume under
the same source validity and receipt bindings. The October trial recorded two refinement splits to depth two. The November
trial recorded eight splits to depth four and retained ten effective leaves. Answer quality has no semantic evaluation in
this test.

The separate `agent-cooperative-browser-discovered` candidate selects
`--model-profile smollm2-360m-v1 --discover-peers --refine-incomplete --refinement-levels 4`. It preserves the public README,
question, browser revision and consent boundary, but selects a literal 4096-byte
UTF-8-safe prefix rather than the original 3840-byte prefix. The existing pinned
360M profile is used without enlarging its limits. Real tokenizer preflight found
the original prefix fits in one 1002-token prompt at this profile, so it cannot
demonstrate the required two-peer partition. No source padding or repetition is used.
The actual 4096-byte preflight produces two parts: 3967 bytes at 1024 prompt tokens
and 129 bytes at 131 prompt tokens. Its retained plan passes this trial's validator
(receipt SHA-256 `58462a6e2f253c6821d82f5c15d6c6fa58bae2e75f114b5136c6c9dfd1c29594`).
This is tokenizer-only evidence, not model execution or a quality/balancing claim.
The reports explicitly identify the
`discovered-360m` contract: complete byte coverage across at least two source
parts, both actual discovered executors, at least one completed synthesis level,
original model/receipt bindings and a complete displayed answer. The selected
cohort and actual executors are verified separately; peer order is not prescribed.
Live cancellation, protected transport and full owned-state cleanup remain required.
This is a distinct trial, not a relaxed rerun of the original fixed-135M contract
(at least five parts and two synthesis levels). Neither answer quality nor
automatic model-profile choice is established by passing either contract.

An independent root observer allows explicit UI submission only after proving prefill
created neither a task nor a peer worker. A public, literal README prefix is partitioned
using the pinned 135M tokenizer. The checker requires complete byte coverage, both peer
executors, at least two synthesis levels, original exact terminal receipts, observed
isolated workers and the hash of the final worker answer matching the browser display.
It then authorizes a second task, observes a live peer worker and permits scoped UI
cancellation. All observed processes must end before cleanup is reported.

The browser gets a loopback-only network namespace and read-only host view; only its
owned proof/profile roots are writable. The coordinator and workers stay under the
existing owner/privilege and protected-route boundaries. The fixture removes its
profiles, input, receipts, publisher identity, model/runtime copies and transient
services. Physical privacy captures and unchanged guest-host snapshots remain required.
The VM collector exports a closed set of bounded structural JSON, fixture/model/source
hashes and host-state evidence; raw prompts, answers, service logs and profiles are not
uploaded. Model answers may still be wrong: successful execution does not prove semantic
correctness, private peer inference, broad agent intelligence or full alpha completion.

Preview without mutation:

```sh
sh tests/integration/run-alpha-topology-vm.sh --preview --scenario agent-cooperative-browser
sh tests/integration/run-alpha-topology-vm.sh --preview --scenario agent-cooperative-browser-discovered
```

The GitHub alpha-topology workflow runs the real disposable scenario at its exact source
revision. Acceptance invokes `agent-cooperative-browser.py report REPORT SOURCE_SHA`;
missing consent, workers, native receipts, hierarchy, transport evidence or cleanup fail
the gate rather than silently substituting a fake service or local-only inference.
The discovered scenario uses the same checker with the explicit leading selector
`--trial discovered-360m`; cross-contract evidence is rejected.

## Recorded trial outcomes

Each row refers to the Core and Browser revisions used by the recorded trial.

| Trial | Recorded outcome |
| --- | --- |
| Fixed-135M `37037361187`, Core `c0362ba5` | Eleven terminal receipts and cleanup; ten leaves reach token limit, no synthesis. Failed answer/display/cancellation acceptance. |
| Discovered-360M `37042900209`, Core `e04860bc` | One EOS and one token-limited leaf, no synthesis or live cancellation proof; cleanup passes. |
| Retained recovery `37052601519`, Core `abb30f34` | Four workers, two terminal receipts; unconfirmed child exchanges and insufficient event-window coverage. Failed normal task cleanup, despite later forced fixture cleanup. |
| Later discovered trial `37058432693`, Core `b76b8a24` | Four terminal receipts and normal task cleanup; incomplete answer, no synthesis, child generation-ending subtype unavailable. Failed panel proof. |
| Discovered-360M `37207405766`, Core `7621087a` | Two source parts, two refinement splits, four EOS leaves and one EOS synthesis. The browser completed and observed cancellation of its second task. Failed the worker-lifetime check before broker stop. |
| Inventory trial `37209763534`, Core `434431d8` | Stopped before connecting or starting work. Final cleanup removed all owned objects and the guest network snapshots matched. |
| [Discovered-360M 44434704508](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434704508), Core `0efdac51`, Browser `326ce0f2` | ESR 140.16.0 displayed the verified answer after 21 signed jobs, ten effective leaves and two synthesis levels. The second task reached scoped cancellation. Panel and worker observations passed. The overall trial failed route continuity. |

The November panel ran with loopback as its only interface and a read-only
host view. Prefill dispatched no work. The two executors matched the two
discovered peers, and the displayed answer hash matched the verified result.
Independent observers confirmed that all 23 observed workers ended and the
fixture removed its model runtime, private job roots and publisher key.

The initial route context was `974ca711032f3c6177157c1a69091737`. The live
sample after the panel completed returned `9d1373dff2bdba9376f31ab29f05b38b`.
The Exit capture recorded 615,881 and 564,388 response payload bytes for the two
providers. The first and last observed workers started at 74,607 and 171,892
Linux clock ticks since guest boot. At 100 ticks per second on x86-64, their
starts alone span 972.85 seconds. The route existed before the first worker
and the final comparison followed the last. The default route lifetime was
600 seconds and the product limit was 900 seconds. The original context could
therefore no longer be valid at the end of this trial. Its replacement time
and the route for each intervening flow were not recorded.
The fixture stopped before its remaining phase-specific transport checks.
Cleanup left zero owned topology objects and both guest-root snapshots had
SHA-256 `3db64e4fb6d345423adbd76f7ee84a6a6fe6a5b8b6f8185c210906a4ec7fc4cb`.
The original Actions ZIP had SHA-256
`657872ae41b2d7c768a476b75a852355088c67c07a42e6d7382368996c7fb11c`.
[Retained byte-exact reports](development/evidence/browser-cooperative-44434704508)

The discovered-360M trial now starts the shared protected-route observer
before the panel can authorize its first task. The observer brackets the
control-relay query with two matching live path observations and joins fresh
Exit completion events to those route contexts. It requires a completed flow
on both the starting and final context, an unbroken sequence of overlapping
Exit-log samples and at least six completed protected flows. Each sampled
context must retain the original physical control relay, both data relays and
the Exit. The five private packet captures and both provider exchanges remain
part of the final acceptance check.

On Core `19fdeedf`, two discovered peers executed the 4,096-byte public Firefox
selection. The first task completed 21 jobs with two synthesis levels. The
second task cancelled two live workers and reconciled both terminal receipts.
The independent observer verified consent before dispatch and the termination of
every observed worker. The route sampler stopped after 114 valid samples and
287 completed flows, with zero failed flows counted through that sample. Its
`route_binding/invalid` result identifies the operation but leaves the specific
comparison unresolved. The guest restored its original host state and retained
zero topology objects. The full trial failed the route check. The 36,785-byte
original ZIP has SHA-256
`adcc978cceb01bd0a358f12dc35755cf7adabc8659f056b3ac4f2f31b088faf9`.
[Hosted trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45424897092) · [Original reports](development/evidence/browser-cooperative-45424897092)

On the integrated Core `442cd948`, the first task again completed its 21 jobs
and two synthesis levels. The second cancelled two live workers. Both tasks
confirmed cleanup. The sampler identified a timeout querying `content status`
after 112 valid samples and 283 completed flows. It had counted zero failed
flows at that point. The complete route claim remains open. The guest restored
its host state and retained zero owned objects. The original 36,798-byte ZIP
has SHA-256 `5db37edd7389e541c2a0da6fa7b7536deb8e3db6b7fd217a0860f637f33b6b03`.
[Hosted trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45506355803) · [Original reports](development/evidence/browser-cooperative-45506355803)

The worker-lifetime observer formerly counted the persistent broker among the
task's transient workers. The correction excludes only the recorded broker
PID and start time before deliberate broker shutdown. Every observed transient
descendant must finish. The failed inventory trial never reached this check.
[Original October source and observations](archive/IMPLEMENTATION_STATUS_20261023.md.txt#L8884)

The [earlier trial records](archive/implementation-notes-20261026.txt)
retain failures, source fixes, receipts, artifact/log digests and diagnostic
limits. An empty sampled event ring cannot prove that the whole run had no failures;
forced teardown cannot replace terminal receipts or confirmed normal task cleanup.
For later integration evidence and next work, use [implementation status](IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence).
