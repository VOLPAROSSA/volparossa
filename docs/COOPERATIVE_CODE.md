# OpenCode to real cooperative execution

Two separate trials cover different application boundaries. The newer public
single-file owner-helper trial passes; the original native OpenCode / two-peer
document trial below still fails answer completion. Neither proves protected
execution of private code on other clients.

## Public single-file proposal: passed development milestone

[Run `37221727043`](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/37221727043)
passes the original `agent-cooperative-code-proposal` checker on core
`2a1b4ad347b7d9f12a6a4c2beee40ff8706bd477`. Workflow source is
`54af18cc5d30a880e3be298192af150daf01b805`; the actual Node owner driver remains
the immutable `f27576ebd7e7ded2f1319186f34df87f48e970d7`.

The owner explicitly publishes one bounded, GPL-3.0-only source file and task.
The core discovers a real Qwen3-0.6B executor; no owner-side model is required.
The original peer model returns a complete 31-byte source replacement at EOS
after 12 tokens, with no repaired text or supplied answer. The initial tests fail.
Separate owner edit permission then applies that exact proposal only to the
selected, base-hash-bound file; separate test permission runs the unchanged
three-test fixture and independent verification successfully.

Discovery and task captures are separated by an actual control-response and
kernel-stream drain barrier. The observer forwards original bytes and generates
no response. Both phases pass their original protected MPTCP and privacy gates;
task traffic goes only to the selected executor. Original source, model, dataset
and terminal job receipts are joined independently. Final observer/service/worker
and private-state cleanup passes, zero owned objects remain, and guest-network
snapshots match. The inventory gate first observes all required relays and exits.

This proves the public owner-helper chain, **not a native editor UI or autonomous
OpenCode planning turn**, broader coding ability, confidential private-peer
execution or complete immune-system review. Earlier failed trials keep their
original status and evidence. Exact artifact, report and log hashes and the
failure chronology are in the
[implementation ledger](IMPLEMENTATION_STATUS.md#explicit-public-code-proposals-bounded-peer-repair-passes).
Replay against the integration branch is not a new live combined-source trial.

## Original native OpenCode / two-peer document trial

This disposable integration connects the source-built OpenCode runtime in
`volparossa-code` to the core's public cooperative service and two real model
workers. It reuses the existing protected MPTCP topology, peer receipts and
cleanup machinery. Its first live VM trial on core `938c7f2b` completed real peer
execution but failed because the answer was incomplete; end-to-end acceptance
remains open.

The private planning turns are deliberately synthetic in this fixture. The
public-core endpoint, peer workers, fragment execution and returned result must
be real. This separates the network integration from the independent, currently
unsuccessful Qwen coding trial; neither is evidence of confidential peer execution
or general coding quality.

## Current live result

VM01 returned the original public tool result through actual OpenCode, without
injecting public results. Two providers ran eleven observed workers; all eleven
terminal receipts and their cleanup were confirmed. The core nevertheless
returned `incomplete_fragment_answers`: eleven parts across three packages,
zero synthesis levels and zero answer bytes. The driver correctly failed with
`public_answer_incomplete`; the observer failed at its final retained-result
completeness check, not an earlier worker scan. The original reports remain failed.

Guest cleanup removed every owned object and guest-network snapshots matched.
QEMU, its scratch directory and SSH listener were removed. The outer host's raw
IPv6-route hash later differed, while IPv4 and DNS hashes matched. Without the
original table contents its cause is unknown; this run does **not** prove the
outer host unchanged. Original closed evidence is retained in
`build/cooperative-code-vm-01/`; no private task logs or answers are exported.

## Explicit inputs

Prepare the bundle with `volparossa-code/scripts/pack_opencode_cooperation.py`.
The current fixture requires Code revision
`b3a4cfe79158d24e1dd61dcb56d37123f9d3d55c`, source-built OpenCode commit
`aec0b9a6d8898f68f923aaf08b7306d931fd9d76` and pinned Node 24.19.0.
An explicit manifest binds the 25 required source, runtime and license files.
No repository credentials, editor history or private project enters the bundle.

```sh
tests/integration/run-alpha-topology-vm.sh --preview --scenario agent-cooperative-code
tests/integration/run-alpha-topology-vm.sh --execute --yes \
  --scenario agent-cooperative-code \
  --image /absolute/pinned/debian-13-genericcloud-amd64-20260826-2582.qcow2 \
  --mpquic /absolute/source-built/volparossa-mpquic \
  --expected-commit EXACT_CLEAN_CORE_REVISION \
  --code-bundle /absolute/code/build/opencode-cooperative-inputs-01 \
  --code-manifest-sha256 EXACT_MANIFEST_SHA256 \
  --output /absolute/new-empty-output
```

The runner validates and captures only the allowlisted bundle files, verifies
the transferred archive, and rechecks every file before execution in the guest.
It never installs these runtimes on the development host. Guest provisioning,
network changes and privileged operations remain inside the disposable KVM VM.
An already prepared workspace-only QEMU toolset can be selected explicitly with
`--host-tools-directory`; the unchanged verifier and pins from core `708bcdd`
check it before use. The runner does not prepare or download host tools. Code
trial scratch is an exact temporary sibling of the output directory, so selecting
an SSD output avoids storing the VM disk in a RAM-backed `/tmp`.

## Required evidence

The owner explicitly enrolls a bounded public README excerpt, question and
GPL-3.0-only license. OpenCode can invoke the enrolled tool but cannot substitute
private conversation context or access the raw public-service socket. The core
owns planning, peer selection, worker supervision and cleanup.

A successful report must join the original tool result to the unique retained
source-manifest digest, actual observed workers, terminal peer receipts and
protected-path payload. The wire task ID is not assumed to be the independently
randomized task-directory name. At least two execution providers, completed
hierarchical synthesis and confirmed cleanup are required. A complete execution
with an incomplete answer remains a failed integration trial.

Only the explicit structural JSON inventory is exported on success or failure;
raw prompts, answers, service logs and private task state are excluded. The
fixture checks account-home cleanup, owned units, private roots and unchanged
guest-host networking. It does not claim live peer cancellation, real model
planning, answer correctness, protected private peer execution or full alpha
completion.
