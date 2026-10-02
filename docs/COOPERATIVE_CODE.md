# OpenCode to real cooperative execution

This disposable integration connects the source-built OpenCode runtime in
`volparossa-code` to the core's public cooperative service and two real model
workers. It reuses the existing protected MPTCP topology, peer receipts and
cleanup machinery. The scenario is implemented but has not yet passed a live
end-to-end run.

The private planning turns are deliberately synthetic in this fixture. The
public-core endpoint, peer workers, fragment execution and returned result must
be real. This separates the network integration from the independent, currently
unsuccessful Qwen coding trial; neither is evidence of confidential peer execution
or general coding quality.

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
