# Cooperative browser: real public peer execution

Status: implemented candidate; the latest combined live KVM attempt confirms all eleven
original terminal receipts and coordinator cleanup, but still fails the joined browser
result. Complete browser/peer acceptance remains pending. Local pure fixture checks are
not a browser, model or network execution claim.

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
```

The GitHub alpha-topology workflow runs the real disposable scenario at its exact source
revision. Acceptance invokes `agent-cooperative-browser.py report REPORT SOURCE_SHA`;
missing consent, workers, native receipts, hierarchy, transport evidence or cleanup fail
the gate rather than silently substituting a fake service or local-only inference.

## First live attempt and bounded driver correction

[Run 36728657126](https://github.com/VOLPAROSSA/volparossa/actions/runs/36728657126)
on core `7c82fc76ab9a2b4256dfd95f428199a0884bd705` and browser
`3c7894168ce6c1f28e96ce5b95bc99928e6c4304` **fails**.
The original 18-file artifact ZIP has SHA-256
`9820ccb3e63490d8675d2a12bbf8c516e2a34b6f0dd99fa2127e78b616bfbdae`.
Gecko reaches the panel driver, but its closed diagnostic records only
`panel-cleanup / SCRIPT_FAILED`: a `finally` status update hid the preceding failure
phase. No WireGuard data or provider application payload was observed in this phase;
there is no combined answer, peer execution or cancellation proof.

Source inspection identifies a deterministic fresh-marker defect. The driver calls
`nsIFile.isSymlink()` before creating `pre-consent.json`, whereas the pinned
[Gecko implementation](https://hg.mozilla.org/releases/mozilla-esr140/file/d864999404b3032f682d74ccc60d1ce38c9ce609/xpcom/io/nsLocalFileUnix.cpp)
returns an error when `lstat` finds no such file. The correction in browser `326ce0f2`
creates new markers atomically with `PR_CREATE_FILE | PR_EXCL`, still rejecting existing
files and dangling symlinks; only the existing private status file may be replaced. It records failure
before `finally` so cleanup cannot overwrite the original phase. Focused pure helper
checks cover these semantics; they do not convert the failed run into a pass.

That original attempt nevertheless reports complete cleanup with zero owned objects
remaining and all four private-job cleanup checks true. The original before/after
host-state files are byte-identical, SHA-256
`2ab5456d7d3aea708e6564b060e41d7476b66fb1a4908c0f1e6d83516edfb474`.
Acceptance still requires a new source-bound run with the real peer result, original
receipts, cancellation and cleanup checks intact.

## Retained-handle reconciliation and flow capacity

[Run `36746682885`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36746682885)
on core `3f47bbef16bc78ebf45e5c6e98102e08e6463bb9` records six original handles but
only four terminal receipts. The implemented reconciliation polls both missing handles;
both exchanges remain unconfirmed, without reaching its deadline. Neither document nor
answer execution is complete. The terminal-receipt gate correctly quarantines admission.
Cleanup is complete, zero owned objects remain, and host snapshots are identical.

Independent source inspection identifies a real route-lifetime accounting bug: the helper
retained issued MPTCP flow capabilities after sockets closed, exhausting its 64-flow bound.
The new terminal operation closes the exact descriptor-bound socket and obtains a worker
ownership-release ACK before reclaiming its ledger slot. It does not increase the live
flow limit, reuse handles, resubmit compute jobs, extend leases or fabricate terminal
receipts. Tests of the ledger are not proof of more than 64 real overlay transfers; that
requires the next executable trial. The older artifact lacks enough stage evidence to
attribute its failed exchanges conclusively to this defect.

The next fixture additionally retains bounded counts of existing fixed compute-RPC stage
codes. It reads at most the 1,000-record agent ring, reports whether it covers the explicit
phase baseline, and exports only the allowlisted failure counts. Raw event records,
session/path identifiers, model inputs, replies and service logs are not exported. A
missing, invalid or incomplete observation cannot become a success claim. Seven focused
fixture checks pass, including baseline filtering and rejection of private/unknown data.

## Completed receipts, incomplete joined result

[Run `37021201299`](https://github.com/VOLPAROSSA/volparossa/actions/runs/37021201299)
on `610866b8770b63719ec1f4b4ce6abb6a83a596ef` retains eleven original handles and eleven
terminal receipts: document execution and local/remote cleanup are confirmed, without
reconciliation. Its event ring covers the phase baseline with zero allowlisted RPC
failures. The original artifact ZIP SHA-256 is
`f4396c04deba99d81eac3e4d7d5769bd4ece01e31e6f235fe3d5088061c281f4`.

The run nevertheless **fails**. Answer completion is false; Gecko reports
`first-task / cleanup_unconfirmed`, and the observer exits with status 1. The original
artifact has neither the observer's failure reason nor a retained wire reply. Its
ordering therefore cannot establish whether browser termination caused unfinished
work, or another failure caused the connection to close. The browser contract accepts
an incomplete answer with confirmed cleanup; those fields alone do not explain the
observed error. No completed display, synthesis/cancellation proof or improved model
quality is claimed. Fixture cleanup succeeds with zero owned objects; before/after
host snapshots both hash to
`ec97a4e9bcf30dc3013bf5ba98d0abc1ed3ea1772107a3f99733e9ff976f081c`.
