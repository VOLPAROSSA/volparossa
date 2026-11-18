# Cooperative browser: real public peer execution

Recorded source-bound candidate: the last trial documented below starts four
workers and retains all four terminal receipts with normal task cleanup confirmed.
Its answer is still incomplete; child ending subtypes were not exported. The joined
browser result, synthesis and cancellation proof remain incomplete. Local fixture
checks are not a browser, model or network execution claim.

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
choice or cross-job answer continuation. Completed browser/Code live trials used
fixed peers, so they do not prove this new service discovery path.

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
the same source validity and receipt bindings. Actual end-to-end model recovery is
still unproved; EOS alone is not proof of answer correctness.

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

These are source-bound historical checkpoints, not new runs on the current source:

| Trial | Recorded outcome |
| --- | --- |
| Fixed-135M `37037361187`, Core `c0362ba5` | Eleven terminal receipts and cleanup; ten leaves reach token limit, no synthesis. Failed answer/display/cancellation acceptance. |
| Discovered-360M `37042900209`, Core `e04860bc` | One EOS and one token-limited leaf, no synthesis or live cancellation proof; cleanup passes. |
| Retained recovery `37052601519`, Core `abb30f34` | Four workers, two terminal receipts; unconfirmed child exchanges and insufficient event-window coverage. Failed normal task cleanup, despite later forced fixture cleanup. |
| Later discovered trial `37058432693`, Core `b76b8a24` | Four terminal receipts and normal task cleanup; incomplete answer, no synthesis, child generation-ending subtype unavailable. Failed panel proof. |

The [complete original trial records](archive/implementation-notes-20261026.txt)
retain earlier failures, source fixes, receipts, artifact/log digests and diagnostic
limits. An empty sampled event ring cannot prove that the whole run had no failures;
forced teardown cannot replace terminal receipts or confirmed normal task cleanup.
For later integration evidence and next work, use [implementation status](IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence).
