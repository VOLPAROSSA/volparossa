# Explicit native CPU inference candidate

This is an **opt-in experimental backend**, not a working-model or coding-quality
claim. The legacy PyTorch backend remains unchanged. Only owner-authorized local
private conversations using `qwen3-4b-instruct-2507-v1` and explicit `greedy_v1`
are eligible. This does not enable private execution on arbitrary peers.

## What is fixed

- llama.cpp source: `7fe450e19305b828c199d602c23a8337aaa1f03b`, the resolved
  `v0.5.0` tag, from `https://github.com/ggml-org/llama.cpp.git` (MIT). The tag is
  unsigned; its name is not executable authorization.
- Qwen source: `Qwen/Qwen3-4B-Instruct-2507` at
  `cdbee75f17c01a7cc42f958dc650907174af0554` (Apache-2.0). The original three
  safetensors shards and their concatenated raw-byte digest remain the model
  identity. A GGUF has its **own** measured size and SHA-256.
- CPU only, AVX2 + FMA + F16C explicitly required and checked before backend
  initialization. No assumption that AVX2 alone proves the other instructions.
  Original upstream fallback builds without FMA/F16C did not compile; no
  permissive compiler flags or undocumented source patches were substituted.
- No HTTP server, network downloads, tool execution, GPU offload, quantization,
  context shifting, hidden warmup, smaller-model substitution or extra time.

`adapter.h` is VOLPAROSSA ABI v1. Python passes bounded scalar arrays and opaque
handles, never guessed upstream struct layouts. llama/ggml and the C++ runtime
are statically linked into the owned library; only the checked platform C/math
loader libraries remain dynamic. Arbitrary dynamic search paths are rejected.

## Source build and conversion

`../build_llama_cpu.py` consumes a clean local checkout of the exact commit. It
does not acquire source, install dependencies or load a model. Preview is the
default; `--execute` builds at low priority with at most two compiler jobs into
a new output directory. `build.json` retains the source/tree, wrapper hashes,
compiler versions, actual library hash, CPU requirements and dependency list.
Original upstream notices are copied unchanged.
The actual static GCC runtime archives are hashed; their original Debian GCC
copyright/runtime-exception notice is retained alongside upstream notices.

The optional `--checks --sanitize` build runs an owned inert ABI smoke, a
separately scoped BF16/F32 wrapper, and the unchanged upstream all-type synthetic
tensor test under ASan/UBSan. Such artifacts are marked **not provisionable**.
These are not model or performance tests; the wrapper does not replace or
change the all-type test or its tolerances.

The original all-type sanitizer check **failed** on a misaligned `uint32_t`
load in upstream `ggml/src/ggml-cpu/arch/x86/quants.c:590`,
`ggml_vec_dot_q1_0_q8_0`. Its retained 412-byte log has SHA-256
`37e07701e4f9a7fadbee0876f77d7eb034192e951a4cd2da572606255bf84f08`.
Q1_0/Q8_0 model tensors are not admitted by this BF16/F32 conversion contract,
but the finding remains unresolved and is recorded in normal build provenance.
The full sanitizer suite must not be described as passing.

A separate owned wrapper reused the original upstream BF16 conversion,
reference and dot-product functions and tolerances, plus its F32 vector cases.
That narrower ASan/UBSan check passed with no model loaded; its 1,776-byte log
has SHA-256 `6fac1d1773ae750583092ed00014e40983d319811a67afea385cc014fe514e46`.
The original all-type failure and source archives were verified unchanged.

`../convert_llama_cpu.py` requires the existing explicit disposable guest/CI
guard, original pinned runtime/model files, local pinned source and a matching
normal source build. It uses the upstream offline BF16 converter and then
independently checks all 398 tensor names, shapes and values against the
original shards. Norm/one-dimensional tensors may be promoted from BF16 to
F32 **exactly**, including signed-zero bits; arbitrary F32 matrices, F16,
quantized tensors, changed values or converter fallback are rejected. The
reported precision is `bf16_with_exact_f32_norms`, not a claim that every
stored tensor is BF16.

The converter also checks model parameters, vocabulary IDs, merges, EOS and the
original chat template. Runtime prompt encoding and output decoding still use
the pinned Hugging Face tokenizer, not an alternate llama.cpp chat template.

`../provision.py --model-profile qwen3-4b-instruct-2507-v1` accepts the optional
pair `--native-cpu-source ABS --native-cpu-build ABS`. Conversion shares the
**original** provisioning disk budget and deadline; insufficient room or time
is a refusal, not permission to raise limits. The new `native-backend/` artifact
has owner-private directories (`0700`) and read-only files (`0400`). Existing
provisioning without these options retains its original behavior/report shape.

Only this explicit conversion adds the official CPython 3.13/Linux x86-64
`sentencepiece==0.2.1` wheel, making 39 wheels instead of the unchanged baseline
38. `native-converter-pins.json` and `native-converter-requirements.lock` bind
its exact URL, 1,387,882-byte size and SHA-256; provisioning retains the combined
pins/lock and includes the extra bytes in the same budget. This dependency is
required even for Qwen's non-SentencePiece vocabulary: the pinned upstream
converter imports SentencePiece before checking for the absent `tokenizer.model`
and taking its normal vocabulary fallback. No upstream patch is substituted.
The wheel's metadata was inspected without installing/importing it on the host;
its version/import check runs only in the existing disposable provision runtime.
The published wheel is not claimed to be a reproducible local source build.
Original release and bundled dependency licenses are retained unchanged and
copied into converted artifacts; the wheel itself contains no license files.

The converter child remains in the existing owned provisioning process group.
On a local timeout or TERM/INT/HUP, its wrapper joins that exact child before
returning, without signalling the shared parent group. If an outer timeout
SIGKILLs the wrapper, its handler cannot run: the child still belongs to the
original group, which the fixture must terminate and join. Harmless real-process
tests cover both cases, including a SIGTERM-ignoring child and an unrelated
surviving sibling. This does not replace the fixture's final group-cleanup check.

## Execution and trust

The owner explicitly supplies `--native-backend-root` and
`--native-backend-sha256`, the hash of the actual `backend.json`. Self-declared
peer metadata cannot authorize executable loading. The core maps the selected
directory read-only; the isolated worker verifies the manifest and complete
library/GGUF/build hashes **before** loading the fixed library.

All original prompt tokens are supplied in batches of at most 128 tokens;
batching does not truncate or restart the context. The same KV state is retained
across pause/resume. Only actual generated EOS ends a successful generation;
raw model text still passes through the existing strict native tool parser and
owner approvals. A proposal is not permission to edit or run commands.

Native callbacks buffer bounded original control frames without acknowledging
pause while computation is active. Cancellation/deadline becomes a fixed abort
status; exceptions are propagated only after native execution has joined. Pause
and resume are acknowledged at stopped decode boundaries by the existing owner
protocol. All handles are closed deterministically, and the supervisor retains
its independent hard-budget and process-cleanup authority.

Actual guest conversion, memory/performance feasibility, real EOS completion and
the unchanged OpenCode read/edit/test scenario still require their own evidence.
Passing a source build, ABI smoke or synthetic tensor test does not establish any
of those outcomes.
