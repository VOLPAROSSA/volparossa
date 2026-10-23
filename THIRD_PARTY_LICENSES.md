# Third-party software and notices

Original VOLPAROSSA source in this repository is licensed under GPL-3.0-only. Dependencies and
vendored components retain their own licenses. This file is a provenance record, not a substitute
for the license text shipped by each upstream project.

## Explicit llama.cpp CPU inference candidate

The optional `qwen_tagged_tool_json_v1` profile also uses the pinned internal
`src/llama-grammar.h` API for grammar initialization, cloning, string acceptance,
candidate filtering and freeing. VOLPAROSSA's `output-constraint.h` and `.cpp`
wrap this unchanged upstream implementation; they are original GPL-3.0-only
code, not an upstream patch. Build manifest v3 binds these wrapper files along
with the existing adapter and loader patch. Synthetic-piece tests link the exact
grammar engine without loading a model. API compatibility and sanitizer behavior
require a fresh source build; previous backend receipts do not validate this
extension.

The opt-in CPU backend uses [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp)
at exact commit `7fe450e19305b828c199d602c23a8337aaa1f03b` (resolved release tag
`v0.5.0`; MIT). The tag is unsigned. No prebuilt upstream executable, server,
GPU backend or implicit artifact download is used. The original checkout remains
unchanged; the build applies the explicitly recorded loader and CPU patches below
to fresh staged copies. The GPL-3.0-only adapter exposes a fixed owned C ABI and
source-build flags.
The builder preserves tracked upstream licenses/notices, including ggml and
the Mozilla tinyBLAS notice, unchanged in the generated artifact.
Static GCC runtime archives retain measured hashes and the original Debian GCC
copyright/runtime-exception notice; compiler versions are recorded, not silently
treated as upstream llama.cpp source or reproducible-build proof.

`workers/volparossa-ml/native-cpu/bounded-tensor-validation.patch` changes both
asynchronous tensor-validation launches to deferred, single-thread execution and
polls the existing cancellation callback between validation results. It preserves
every tensor check, error aggregation and final completion callback. The MIT
upstream code and notices retain their original license; the surrounding owned
adapter and test harness remain GPL-3.0-only. Build manifest v2 records the clean
tree `fd570ef54b10ec5fecb739e7e04c8ce44a6f415a` and these SHA-256 digests:

- Original `src/llama-model-loader.cpp`: `efdb5f273bd1ab77301f2cadea1a5a804bafb28040aca033e45605a97a450242`.
- Patch: `388fff7d5d9ca812abfeb27fddd1629144b7de6284e4bf685fbc8c147891e8c1`.
- Effective staged loader: `fcd26ea4ae21ea04954b275287c41a35e383015b736bbbe2e68f2ab5f6d095f9`.

The builder verifies that the compilation database selects exactly the staged
loader. It rejects changed source/patch bytes and retains the clean upstream
checkout and original notices. This is a local patch, not an upstream release.

`workers/volparossa-ml/native-cpu/q1-aligned-load.patch` replaces one AVX2
pointer-cast load in `ggml_vec_dot_q1_0_q8_0` with a 16-byte `memcpy` into an
aligned four-element `uint32_t` array. Arithmetic, quantization formats and the
upstream all-type test remain unchanged. The original MIT license is preserved.
Build-v4 provenance records this separate `cpu_source_overlay` and checks both
the selected translation unit and its compiler command against the staged file:

- Original `ggml/src/ggml-cpu/arch/x86/quants.c`: `3c489fdc77e3ab484a5f188bff9c60c0e9483c951ed65c1a562a04c249d5628e`.
- Patch: `563a178667eeac17e7072c343d1d21a3f641d78c284acbeb2633db26e1c36369`.
- Effective staged CPU source: `b9a63f032ad048a688357194fa535d852959ffee0942c93d4b8fb9544febf6d2`.

Historical builds omit this provenance pair and do not establish the correction.
The source-only normal and sanitizer builds must verify the new source before
its acceptance; no existing failed sanitizer result is replaced or suppressed.

The separate offline conversion candidate starts only from the existing pinned
Apache-2.0 `Qwen/Qwen3-4B-Instruct-2507` revision
`cdbee75f17c01a7cc42f958dc650907174af0554`. It compares every original BF16 tensor
value, allowing only exact F32 promotion for norm/one-dimensional tensors; it
does not quantize weights. Original shard identity and the measured GGUF digest
are distinct. The original Qwen license accompanies converted artifacts.
See [the native CPU contract](workers/volparossa-ml/native-cpu/README.md) for
source/build/conversion provenance, instruction requirements and remaining proof.
Source and inert tests are not claims of successful guest inference or coding.

The explicit native conversion, not the baseline 38-wheel runtime, adds the
official [SentencePiece 0.2.1 wheel](https://pypi.org/project/sentencepiece/0.2.1/)
for CPython 3.13 / manylinux 2.27+ x86-64: 1,387,882 bytes, SHA-256
`c7f0fd2f2693309e6628aeeb2e2faf6edd221134dfccac3308ca0de01f8dab47`.
Exact origin, metadata hash and optional lock are retained in
`workers/volparossa-ml/native-converter-pins.json`; it is a pinned published
binary, not a claim of a locally reproduced source build. Its Apache-2.0 release
source is [google/sentencepiece at 31646a467d2051eb904e0b45de3a73e91fe1c1e3](https://github.com/google/sentencepiece/tree/31646a467d2051eb904e0b45de3a73e91fe1c1e3)
(`v0.2.1`). The wheel contains no license files. Original release LICENSE and
the original bundled absl, darts_clone, esaxx and protobuf-lite licenses from
that revision are therefore retained unchanged under
`workers/volparossa-ml/native-cpu/sentencepiece*-LICENSE`, with exact source
URLs, sizes and hashes in the optional pins. Converted artifacts include all
five notices; no notice is replaced by this summary.

## Public SNP verifier fixture trial

The disposable public-fixture workflow selects
[`virtee/sev`](https://github.com/virtee/sev) version 8.0.0 at exact commit
`a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5`, tree
`636379a232b75ad3c0f2a079acc1788dc13a920f`. The upstream Apache-2.0
[license](third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt) is retained
unchanged. One explicit lockfile-only correction is applied as described below.
This is a source-built CI probe,
not a production dependency, prebuilt worker or task-release authority.

The [exact pinset](tests/integration/protected-compute-verifier-pins.json)
records bytes and SHA-256 for the original Cargo.toml, Cargo.lock, license,
four-test target and public Milan certificate/report inputs. The original
lockfile remains available unchanged in the verified upstream Git commit.
The pinned commit updates the `rand` package to `0.8.8` but leaves
`num-bigint-dig 0.8.6` referring to absent `rand 0.8.5`. The
[fixture preparer](tests/integration/protected-compute-verifier.py) changes
only that one reference to `rand 0.8.8`, without changing any package version,
checksum or executable source. Both lockfiles are 66,223 bytes: original SHA-256
`fe1511ef932c1a54d0cd70ac470b41de8357ab2efca9ed6b3a4ea22c3b7d3bd0`,
effective SHA-256 `7b7dbf853cecf44a8d2a6b51283012b446db97600f4e19af36a1c642b8bfa7cb`.
Schema-two pins and result receipts distinguish both identities; only this exact
unstaged change is accepted after pristine-source verification. Rust 1.85.0,
`--locked` and the `snp,crypto_nossl` feature selection
are explicit; native compilation is confined to the disposable hosted runner.
The compiler comes from the pinned-version Rust toolchain distribution, not a
reproduced compiler source build. The upstream checkout and dependency sources
retain their own notices there; neither binaries nor a vendored dependency tree
are distributed by this change. See [trial scope and remaining requirements](docs/development/PROTECTED_COMPUTE_VERIFIER.md).

## Core signature verification dependency

The core [signature-facts module](crates/volparossa-content/src/provider/compute/attestation.rs)
selects the same exact `sev` revision with default features disabled and only
`snp,crypto_nossl`. It uses upstream Milan ARK/ASK bytes as cryptographic reference
roots, not as independently authorized production trust. Its two unchanged
public regression inputs are copied from `tests/certs_data/` into
`crates/volparossa-content/tests/fixtures/snp/`: `report_milan.hex` (2,368 bytes,
SHA-256 `3d956e9104969a038031a6b63dd6c4b60000619d37702065994f7da76f88ae7d`)
and `vcek_milan.der` (1,360 bytes, SHA-256
`3bbfb6ee259f75a95d13168cfdf2e034181bb93c7c016825731cbe8ea16c95e1`). They
remain Apache-2.0 inputs under the unchanged upstream license linked above.
`x509-cert` is constrained to 0.2.5 (Apache-2.0 OR MIT) from
[RustCrypto formats](https://github.com/RustCrypto/formats/tree/x509-cert/v0.2.5/x509-cert)
for certificate validity access; it is also the version in the pinned upstream
lockfile. The workspace now adopts the exact dependency lock compiled and tested
by [core trial 38432553365](https://github.com/VOLPAROSSA/volparossa/actions/runs/38432553365):
143,756 bytes, SHA-256
`f87bfe531b282c83665a066daec181564edf8d256a08a6b024e2d5810f5abbac`.
All 531 original package identities, versions and checksums are retained. The
29 additions belong to the verifier dependency closure; the seven additional
feature edges at existing packages were checked against their upstream manifests.
The 28 new registry archives match their lockfile checksums and retain compatible
upstream licenses; the remaining addition is the exact pinned SEV Git source.
The license collector accepts only that Git identity and unchanged Apache-2.0
license bytes, SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
Current hosted checks use `cargo fetch --locked`, followed by locked/offline
metadata, tests and Clippy. The standalone probe and its separate lock correction
remain historical evidence, not substitutes for the core build.

### RSA advisory scope

`rsa 0.9.10` is affected by
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), which
concerns private-key leakage through timing. It is **not patched** here. The
selected [SEV verification code](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/src/certs/snp/cert_nossl.rs)
uses `RsaPublicKey` and PSS/SHA-384 verification only. Its RSA operation applies
the public exponent to a public signature; no RSA private key, decryption,
signing or key generation is used by this core call path.

The dependency check admits this advisory as non-applicable only after checking
the exact source, features, incoming dependency edges and reviewed verifier
source. It then creates a temporary root-only audit configuration. The ordinary
deny configuration has no global exemption, and the separate fuzz graph neither
uses RSA/SEV nor receives this exception. A changed dependency or use requires
fresh review; this finding is not permission to use RSA private-key operations.

The module has no vendor-collateral downloader or task-release hook. VCEK
extension-to-chip and reported-TCB binding is checked. Production trust, current
vendor security policy and complete worker appraisal remain separate requirements. AMD's
[VCEK and KDS specification 57230](https://docs.amd.com/v/u/en-US/57230), revision
1.05, identifies the product CRL endpoint and certificate extensions. Those
vendor inputs are distinct from local authorization of roots and workload code;
neither is supplied by a peer assertion or a successful signature check.

### Guest firmware quote request

The guest-session candidate reuses the same exact Apache-2.0 `sev` dependency,
features and committed lockfile. Its only additional upstream production call
path is [guest firmware `open` and `get_report`](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/src/firmware/guest/mod.rs):
open the fixed `/dev/sev-guest` device and return the original `SNP_GET_REPORT`
bytes with explicit message-version/VMPL inputs. No extended-report allocation,
certificate downloader, derived-key operation, RSA signing, RSA decryption or
RSA key generation is added. The public-RSA guard separately pins the reviewed
guest source; this does not broaden the advisory exception or the fuzz graph.

The guest's own ephemeral key uses the existing `RecipientKeyPair` implementation,
not this RSA dependency. Original upstream source and notices are unchanged;
there is no new binary, dependency version or local upstream patch. Compilation
or synthetic collection tests cannot establish that actual firmware ran, that
the key is protected from the host, or that the guest is an authorized worker.

### Supplied Milan revocation list

The candidate session verifier also uses `rsa =0.9.10` directly for public-only
PSS/SHA-384 verification of a supplied ARK revocation list. This is the same
Apache-2.0 OR MIT package already pinned in the lockfile, with checksum
`b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d`;
no package version is changed. The exact-source and dependency-graph guard
now covers this second public-verification path. The advisory remains unpatched
and the restriction against private-key operations is unchanged.

The public fixture `ark_milan_20260922.crl` was retrieved unchanged from
[AMD's Milan CRL endpoint](https://kdsintf.amd.com/vcek/v1/Milan/crl) on
2026-10-14 (Europe/Amsterdam). It contains 866 bytes and has SHA-256
`dd68e9e3feb97dd0e95135feeae47d9cc193c73239a6281ec9884c00d5e6a525`.
Its ARK-Milan signature authenticates CRL number 12, valid from
2026-09-22 07:35:42 UTC until 2026-11-09 01:00:00 UTC, with no listed
revocations. This is public issuer-signed validation data, not VOLPAROSSA
source code or a production trust grant; the binary has no local patches.

The closed profile follows AMD 57230 revision 1.05 and
[RFC 5280 CRL processing](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3).
It checks the fixed Milan certificate path and a complete ARK-issued list for
that path's ASK. It does not prove individual VCEK revocation status, absence
of newer collateral, an acceptable firmware version or private execution.
The fixture's validity dates do not authorize future use outside that interval.

## CometBFT ABCI transaction adapter inputs

The TEST-only transaction adapter generates its wire bindings from the official
CometBFT v0.40.0 schemas at commit
`0880b4d378f347ab16e54ec677ff50d803f37d62` (Apache-2.0). The five schema files,
original LICENSE and NOTICE are retained verbatim under `third_party/cometbft/`.
Their Gogo options come from cosmos/gogoproto v1.7.2 at
`cf5213e4dcbf1fea203185c0af00840e566790d9` (BSD-3-Clause), matching the pinned
CometBFT go.mod. The Timestamp, Duration and Descriptor imports come from Protocol
Buffers v21.12 at `f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c` (BSD-3-Clause).
Both projects' original license texts are included unchanged.

[The source manifest](third_party/cometbft/sources.json) records exact paths,
revisions, Git blobs, byte counts and SHA-256 values; no upstream patches are
applied. [The offline verifier](third_party/cometbft/verify.py) checks these inputs
without fetching or executing a consensus engine. Generated bindings and schema
integrity do not establish distributed consensus. A separate source-built
validator fixture must retain its own Go toolchain/dependency provenance and
notices before any runtime result is claimed.

The separate, disposable transaction fixture pins the official Go 1.27.1 Linux
amd64 compiler archive, 70,553,950 bytes, SHA-256
`63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`,
as published in [Go's release metadata](https://go.dev/dl/?mode=json).
This is an explicitly downloaded upstream compiler binary, not a reproduced
compiler source build or a prebuilt CometBFT engine. Its source tag resolves to
`862c888e612ac346c7c4d99c9392bdfd265f33b0`; the unchanged BSD-3-Clause
[LICENSE](third_party/licenses/go1.27.1-BSD-3-Clause.txt) is retained separately.
The complete compiler distribution and its notices must remain intact inside the
guest. CometBFT itself is built there from the pinned source, with automatic Go
toolchain switching disabled and module versions constrained by the original
go.mod/go.sum. No Go installation on the development host is authorized by this
fixture. Source staging and compiler integrity are not evidence of consensus.

## Explicit native editor integration trial

The `agent-native-editor` guest trial uses VOLPAROSSA Code commit
`41a4320f0a819819adcfa9969ed4780506d6c747` (GPL-3.0-only), the already
source-built open Codex app-server at upstream commit
`67727e7cf114cf3e1b71db368d74b24e32f6cb12` (Apache-2.0), and a verified copy
of the installed VSCodium `1.135.06055` package. VSCodium's declared source
commit is `1a46a584725d5dd330e0bcd7f5510f24990efcf2`; this trial does **not**
claim to have reproduced its source build. It uses no proprietary Codex editor
extension. The complete editor tree, including original MIT/Chromium and
dependency notices, is copied unchanged; setuid/setgid modes are not retained.

`tests/integration/agent-native-editor-pins.json` binds every Code input,
the complete editor inventory, native binary/build report, full upstream prompt,
and all 1,824 native notice files. The native report preserves its original
one-file recursion-limit patch and compiler provenance. Packaging reuses that
verified build and does not execute it, download another executable or install
anything on the development host. Guest execution remains a separate test.
The workspace-only Debian QEMU provisioner/pins are reused unchanged from the
native-browser candidate `ca37a68a48a352b3e2edf62a24a10cf7aca84cd0`.

## Explicit OpenCloud client integration trial

The disposable `cloud-private-file` scenario stages VOLPAROSSA Cloud at
`c81980dd71297b257f1df6aa382c28a18f9c2f57`, with each used source file's exact
length and SHA-256 in `tests/integration/cloud-private-file-pins.json`. Original
GPL-3.0-only Cloud integration and its pinned vendor notices remain unchanged.

Its explicit guest-only SDK stage uses the original published
[`@opencloud-eu/web-client` 8.0.0 package](https://registry.npmjs.org/@opencloud-eu/web-client/8.0.0),
under AGPL-3.0. The Cloud source pin retains the exact archive URL and SHA-512
integrity; archive SHA-256 is
`8954d9ad90e44a6f62d0e32d3280ca92fd7b0ce30042fe07cdde5c653e0739b3`.
All 109 original files (1,109,076 unpacked bytes), including LICENSE and bundled
notices, are retained and rechecked before importing the WebDAV SDK. No package
installer or lifecycle script runs. This is a pinned published artifact, not a
claim of reproducible SDK source compilation or a bundled core dependency.
The provision receipt separately binds package inventory and source provenance;
successful staging alone is not evidence of actual SDK or protected-peer reads.

The original Files UI is built explicitly inside the disposable guest from
[`opencloud-eu/web`](https://github.com/opencloud-eu/web/tree/11e699ac82fda4dd113ac3ceb2ecb2dd74574045)
revision `11e699ac82fda4dd113ac3ceb2ecb2dd74574045`, tree
`4f13ceee9b21450659266df69a4fac57f25c3bc9`, under AGPL-3.0. The pinned Cloud
source retains its upstream license, frozen dependency lock and separately recorded
owner-recovery patch (`f7d26672d3a571f7beceb65b3bffffaedcc4191a9f9e59cef30d0dba56cb8064`).
Its pinned pnpm 11.27.0 package retains the original MIT license and SHA-512
integrity from `third_party/opencloud-web-ui.json`. Dependency lifecycle scripts
are disabled; the build itself runs offline as the disposable unprivileged user.
Every output asset is inventoried before copying into the read-only runtime.
The guest reuses the separately pinned Firefox ESR 140.16.0 runtime from
`browser-network-pins.json`, preserving Debian's original copyright notice.
Neither successful source compilation nor verified browser staging establishes
that the UI has retrieved a file from protected peers; that requires the joined trial.

## Explicit Image and Cloud maintenance trial

The consumer continuation of `private-storage-maintenance` separately pins
VOLPAROSSA Image `aade424c3e96d0934edbddf31d2434757aa08564` and VOLPAROSSA Cloud
`9cb94fbb83e9f503ff5a66d43ed814f556d4a3af`. Each staged source file's length and
SHA-256 are recorded in `tests/integration/storage-consumer-maintenance-pins.json`.
Original GPL-3.0-only licenses and the Cloud vendor provenance are retained;
the shared Image adapter, snapshot helper and license must match byte for byte.
These are additional trial pins, not replacements for earlier consumer trials.

The explicit guest-only provisioner reuses verified Node 24.19.0: the official
Linux x64 archive is 31,633,904 bytes with SHA-256
`14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647`.
The unchanged runtime LICENSE contains its bundled third-party notices.
Debian GnuPG and tar package versions and executable hashes are retained in the
provision receipt. No npm install, SDK/browser build, application server or
development-host installation is performed by this profile. Verified staging
does not itself prove peer storage, repair or application restoration.

## Explicit development ML inputs

The disposable native-coding CI build uses a separately licensed AppArmor policy,
`tests/integration/native-coding-bwrap.apparmor`, derived from AppArmor v4.0.1,
commit `b0eb95457bc2de401920308869d016e696c73664`,
[`profiles/apparmor/profiles/extras/bwrap-userns-restrict`](https://gitlab.com/apparmor/apparmor/-/blob/b0eb95457bc2de401920308869d016e696c73664/profiles/apparmor/profiles/extras/bwrap-userns-restrict).
The upstream GPL version 2 [LICENSE](https://gitlab.com/apparmor/apparmor/-/blob/b0eb95457bc2de401920308869d016e696c73664/LICENSE)
is retained unchanged in `third_party/apparmor-ci/LICENSE`, SHA-256
`a7e0cdcbea5c14927cedfc600d46526bdcbb1eb0a4d951e2ea53c2a6de159cb4`.
The policy retains its own GPL-2.0-only designation, separate from original core code.
Local changes (2026-10-01) give both profiles unique CI names and omit host-local
policy includes; capability-denying child stacking and the original explanatory
comments remain. The workflow uses Ubuntu's package-owned `/usr/bin/bwrap` and
adds/removes these profiles only for the selected disposable CI build. It neither
ships this policy in the product nor changes developer-host policy or global sysctls.

The optional, guest-only `workers/volparossa-ml/provision.py` installer is not an automatic
agent update channel. `model-pins.json` and `requirements.lock` pin 38 original CPython 3.13
Linux amd64 CPU wheels and eight original model assets by exact download URL, byte size and
SHA-256. Provisioning retains the original wheel archives and their license files, as well as
the original model `LICENSE` and model card. No source distributions, CUDA packages, remote
Python model code or pickle weight files are allowed. These inputs are not bundled in the
current Debian package; a later distributable ML package still needs complete notice collection.

| Component | Original source / revision | License/provenance scope |
| --- | --- | --- |
| SmolLM2-135M-Instruct | [HuggingFaceTB model](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/tree/83212e1e2b3cfd6958f3707877bb878945dea8ee), `83212e1e2b3cfd6958f3707877bb878945dea8ee` | Apache-2.0; unchanged model LICENSE SHA-256 `59899c6091b540582ed617e8eeaac4919dc985ccfc35459ee9752b699be5205b` |
| Opt-in SmolLM2-360M-Instruct | [HuggingFaceTB model](https://huggingface.co/HuggingFaceTB/SmolLM2-360M-Instruct/tree/a10cc1512eabd3dde888204e902eca88bddb4951), `a10cc1512eabd3dde888204e902eca88bddb4951` | Apache-2.0 declared by the original model card; this revision has no `LICENSE` file. The explicitly pinned, unchanged Apache-2.0 text from the 135M row is retained separately, not described as a file from the 360M repository. |
| Opt-in SmolLM2-1.7B-Instruct | [HuggingFaceTB model](https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct/tree/31b70e2e869a7173562077fd711b654946d38674), `31b70e2e869a7173562077fd711b654946d38674` | Apache-2.0 declared by the original model card; this revision has no `LICENSE` file. The unchanged Apache-2.0 text from the pinned 135M repository is retained with separate provenance, not attributed to the 1.7B repository. |
| Opt-in Qwen3-0.6B private native-tool profile | [Qwen model](https://huggingface.co/Qwen/Qwen3-0.6B/tree/c1899de289a04d12100db370d81485cdf75e47ca), `c1899de289a04d12100db370d81485cdf75e47ca` | Apache-2.0; same-revision original LICENSE, 11,343 bytes, SHA-256 `832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e`. Explicit provisioning retains it unchanged together with the original model card. |
| Opt-in Qwen3-4B-Instruct-2507 private native-tool profile | [Qwen model](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507/tree/cdbee75f17c01a7cc42f958dc650907174af0554), `cdbee75f17c01a7cc42f958dc650907174af0554` | Apache-2.0; original same-revision LICENSE, 11,343 bytes, SHA-256 `832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e`. Original license, model card, tokenizer, index and shards retained unchanged; no upstream template/model patches. |
| PyTorch CPU `2.14.0+cpu` | [pytorch/pytorch](https://github.com/pytorch/pytorch/tree/2b3ec34829036a65cd9d1398ea72a0167dc37470), `2b3ec34829036a65cd9d1398ea72a0167dc37470` | Original official CPU wheel; retain its own and bundled dependency notices |
| Transformers `5.16.1` | [huggingface/transformers](https://github.com/huggingface/transformers/tree/93c8b7b485963a10800c91f55304db6be211c2bd), `93c8b7b485963a10800c91f55304db6be211c2bd` | Apache-2.0; original wheel notices retained |
| PEFT `0.20.0` | [huggingface/peft](https://github.com/huggingface/peft/tree/a5526d27a9d47d1e8264d5e1b1f96c0fdc79464e), `a5526d27a9d47d1e8264d5e1b1f96c0fdc79464e` | Apache-2.0; original wheel notices retained |

Original model weights are 269,060,552 bytes, SHA-256
`5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c`.
This is slightly larger than the current native content-object ceiling; the ceiling has **not**
been silently raised. The initial trained rank-4 adapter fits a normal content object, while
full-model distribution needs explicit compatible sharding/parts integration. No trained
adapter or actual backend execution is claimed until the isolated guest smoke succeeds.

The opt-in `qwen3-0.6b-v1` profile adds nine same-revision assets in
`workers/volparossa-ml/model-pins-qwen3-0.6b.json`, reusing the unchanged 38-wheel runtime.
Original weights are 1,503,300,328 bytes, SHA-256
`f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b`.
The worker uses the original pinned native chat template, with an original GPL-3.0-only
adapter for ordered roles, offered-tool aliases and strictly parsed proposals; the
upstream template/model files are not patched. Metadata verification and offline
bridge tests do not claim downloaded weights, real model execution or tool-use quality.

The separately owner-selected `qwen3-4b-instruct-2507-v1` profile pins twelve
original assets in `workers/volparossa-ml/model-pins-qwen3-4b-instruct-2507.json`
and reuses those same 38 runtime wheels. The complete three original shards were
read and verified against upstream LFS SHA256/length pins. In filename order their
raw concatenation is 8,044,982,000 bytes, SHA256
`79f6bbc34572c0063d12022f0f93074d90bbcd5dfd82134423bf892f7f8df3cf`.
This is the profile's actual weight identity, not a digest of the index or manifest.
The original index is separately pinned, SHA256
`d6c42883a895dfef5b0080ed2116a1bcd764f558406b98923d675978a1abf29c`;
its upstream tensor-size metadata is not the physical shard byte count. Original
source capture report SHA256:
`726ecd894a5b6f2594b980771eafb01448295b5a426f2fd2d778548bfd98ad80`.
This source check installed no runtime and executed no model. Native tool quality,
the candidate CPU memory budget and an actual coding task remain unproved.

The optional `smollm2-360m-v1` inference/planning profile adds seven original model assets
in `workers/volparossa-ml/model-pins-360m.json` and the separately attributed license text;
it reuses the exact 38-wheel runtime lock. Its original weights are 723,674,912 bytes,
SHA-256 `e6bffe7435d7ddc10fd3b9a9efd429dafbacb1cb17015fb5562664e7532bf86e`.
Tokenizer SHA-256 `9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c`
is reused because upstream lists the identical Git blob
`f922b1797f0c88e71addc8393787831f2477a4bd` at both exact model revisions.
No weights or tokenizer were downloaded for this metadata check. The 360M profile does
not enable training or apply 135M adapters, and does not raise the native content-object
ceiling or establish answer quality.

The separately selected `smollm2-1.7b-v1` profile pins its original assets in
`workers/volparossa-ml/model-pins-1.7b.json`, reusing the same 38-wheel runtime.
Original safetensors are 3,422,777,952 bytes, SHA-256
`f55217be716b6a997b97b9d8d7eb6fad02e00858f5010ec24f64603c3a98a0e8`.
The original configuration declares BF16. This inference-only profile explicitly
loads CPU BF16 parameters, checks their actual dtype, and records it in reports;
it does not quantize the file, train, accept 135M adapters, or retry with FP32.
The 135M and 360M profiles retain their original FP32 loading and report formats.
The pinned [Transformers Llama implementation](https://github.com/huggingface/transformers/blob/93c8b7b485963a10800c91f55304db6be211c2bd/src/transformers/models/llama/modeling_llama.py)
uses FP32 softmax/RMS accumulation with casts back to the input dtype; the pinned
[PyTorch CPU BLAS implementation](https://github.com/pytorch/pytorch/blob/2b3ec34829036a65cd9d1398ea72a0167dc37470/aten/src/ATen/native/CPUBlas.cpp)
includes BF16 dispatch. These are source-level compatibility checks, not proof
of guest memory fit, speed, answer quality, or support on every CPU. Only metadata
was inspected for these pins; no model weights or backend were run on the host.

The separate, explicit `--task-graph-decoder` provisioning option appends three original
pure-Python wheels; neither the 38-wheel baseline nor its `requirements.lock` is changed.
`graph-decoder-pins.json` and `graph-decoder-requirements.lock` retain their exact original
PyPI URLs, byte lengths and SHA-256 values. The optional runtime has 41 wheels, adds
235,780 download bytes, retains every original wheel including its unchanged MIT notices,
and validates the actual merged dependency graph before offline installation. The retained
merged pin file and requirements hashes describe the files actually installed. Installation
and the optional core-import/version check run only in an explicitly acknowledged disposable
environment; no model execution or successful constrained generation is implied.

The separate source-bundled `task_graph_decoder.py` adapter also supports explicitly ordered
principle JSON. Its marked source-quote scalar uses canonical JSON string lexemes: upstream
0.11.3's [string-enum state](https://github.com/noamgat/lm-format-enforcer/blob/05c7dc3a46305e39c1a67c8622c433d8deda48a2/lmformatenforcer/jsonschemaparser.py#L476)
does not preserve general escaped source strings as enum values. This is a process-local adapter,
not an edit to the original wheel or its notices. Original output still requires independent
source/UTF-8 validation; constrained syntax does not establish sound model reasoning.
Graph strategy v3 also wraps the pinned parser with per-prefix question/dependency constraints
and ordered compact JSON. This remains separate source-bundled adapter code; no original wheel,
notice or model asset is changed.
Its graph-only traversal adapts the same pinned `TokenEnforcer._collect_allowed_tokens` to
intersect existing tokenizer-trie edges before checking graph predicates. It retains terminal
tokens and authoritative per-character transitions; non-graph shortcuts still delegate upstream.
The original MIT notice remains in the separate adapter.

| Optional decoder component | Exact source / original distribution | License and notice provenance |
| --- | --- | --- |
| LM Format Enforcer `0.11.3` | [release source](https://github.com/noamgat/lm-format-enforcer/tree/05c7dc3a46305e39c1a67c8622c433d8deda48a2), commit `05c7dc3a46305e39c1a67c8622c433d8deda48a2`; [original PyPI metadata](https://pypi.org/pypi/lm-format-enforcer/0.11.3/json) | MIT, Copyright (c) 2023 Noam Gat; original source LICENSE SHA-256 `d1c02373f9da54abb40fb9fa5ca6c19136d10da76a1054ff1ee2528221ae1bfe`. Our separate tokenizer adapter retains this notice. |
| Interegular `0.3.3` | [original release metadata](https://pypi.org/pypi/interegular/0.3.3/json); original source archive SHA-256 `d9b697b21b34884711399ba0f0376914b81899ce670032486d0d048344a76600`, 24,705 bytes, URL retained in decoder pins | MIT as declared by the original distribution; original wheel retained unchanged. No matching `0.3.3` upstream Git tag was found, so no Git-to-wheel equivalence is claimed. The source archive is provenance only, never installed. |
| Pydantic `1.10.24` (pure Python wheel) | [release source](https://github.com/pydantic/pydantic/tree/ebb3e81419f8a1c0b4976b91a22bfb17a3ddf23c), commit `ebb3e81419f8a1c0b4976b91a22bfb17a3ddf23c`; [original PyPI metadata](https://pypi.org/pypi/pydantic/1.10.24/json) | MIT, Samuel Colvin and other contributors; original source LICENSE SHA-256 `9e3946690ac88b6b73e8f001a0586af13568be8852fd514e4393f39761764387`. The pinned optional artifact is not a compiled extension wheel. |

The fixed Rust supervisor uses Debian's installed Bubblewrap and util-linux resource/priority
tools as separate executables, not vendored copies. The sandbox argument vector is part of our
source; [upstream Bubblewrap](https://github.com/containers/bubblewrap) explicitly makes its
security policy the caller's responsibility. No development-host package installation occurs.

## Native MPQUIC audit state

The native MPQUIC input was audited through 2026-08-14. Every upstream
repository, submodule revision, Git tree, origin, license copy, bundled Wintun
file, and local patch is content addressed in
`third_party/upstream.lock.json`. Source retrieval is an explicit `--yes`
operation; verification and builds perform no network access and refuse
unchecked prebuilt binaries. Upstream checkouts under `third_party/src/` and
generated outputs under `native/volparossa-mpquic/build/` are ignored build
inputs, not committed source or release artifacts.

### Locked native source

| Component | Canonical origin | Exact commit and tree | Tag | Upstream license |
|---|---|---|---|---|
| mqvpn | `https://github.com/mp0rta/mqvpn.git` | commit `607c0df921e2c23bae8bea21cb3c6f2acb2db275`; tree `d6c5ff654c5b7be4754bcb8ad2720b112a2b1e56` | `v0.15.1` | Apache-2.0 plus NOTICE |
| xquic | `https://github.com/mp0rta/xquic.git` | commit `6957ccf9b9fcb9ab62c43672638876abe47162dc`; tree `1999a0a944a1c93b46f7b41b9ff4dccb9302966b` | `mqvpn-v0.15.1` | Apache-2.0 |
| lwIP fork | `https://github.com/mp0rta/heiher-lwip.git` | commit `821af1994c4dbaf1e2cba9a7c2207303b3e5327b`; tree `995119cb3b9074644ed8af3d8c2553fe4f3781aa` | none | BSD-3-Clause |
| BoringSSL | `https://github.com/google/boringssl.git` | commit `fd490c05de684d4cf135388023acf9aabb4e54f1`; tree `0420b7c79fdb88ccf2d7cb21bb934da6a0bc4092` | `0.20260730.0` | Apache-2.0 for linked `libcrypto`/`libssl`; BSD-3-Clause only for unlinked Go TLS test support |
| Wintun userspace header | `https://www.wintun.net/` | bundled by locked mqvpn; exact `wintun.h`, `LICENSE`, and `README.md` SHA-256 values are in the lock | bundled with `v0.15.1` | GPL-2.0 OR MIT; mqvpn selects MIT |

The mqvpn parent gitlinks pin xquic and lwIP; the xquic parent gitlink pins
BoringSSL. Verbatim license and NOTICE copies are retained in
`third_party/licenses/` and their SHA-256 values are locked. The Wintun input
is exactly `third_party/src/mqvpn/third_party/wintun/{wintun.h,LICENSE,README.md}`.
The verifier checks all three files and the byte-identical
`third_party/licenses/wintun-MIT.txt` copy; the Wintun license SHA-256 is
`55743868302006ccaa536bcb96903e185999c6a9cb51ff5bf4b41b96bb30fd07`.
The notice is Copyright WireGuard LLC 2018–2021. This header is Windows-only
and is never compiled or linked on Debian; no Wintun DLL is bundled,
downloaded, or loaded at runtime. The verifier also checks full commits,
trees, origins, tags, parent gitlinks, and tracked-tree cleanliness before a
build can start.

The pinned BoringSSL `LICENSE` has SHA-256
`827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f`
and starts with Apache-2.0. Ancestor commit
`33d1049b1f730d2725bb09b2256fd5fe4c46b17e` switched the project license
to Apache-2.0. Its trailing BSD-3-Clause notice applies only to Go TLS test
support that the license itself says is not included in compiled
`libcrypto` or `libssl`. This is a source-provenance scope statement, not
legal advice.

### Reviewed local patches

| Target | Patch and SHA-256 | Purpose and security effect |
|---|---|---|
| mqvpn | `patches/volparossa-mqvpn.patch`; `4ce314d8eb539dc362359f7fb901b6a76c827126b3c7091ee9b04528f556dd34` | Requires a caller-supplied leaf-SPKI SHA-256 pin, propagates explicit path tuples and honest counters, accepts bounded in-memory server PEM identity through sealed anonymous Linux memfds, wipes copied secrets, honours `multipath=false`, bounds pre-H3 mqvpn admission, pins one exact UDP peer, and enforces one lifetime-affine CONNECT-IP claim with idempotent request/connection teardown and duplicate body/Datagram isolation. |
| xquic | `patches/volparossa-xquic.patch`; `52b1a30297fb4793067f00b6695dcdfdfba25d684ae45fdda37dc61bed6f13f9` | Invokes the requested certificate callback for every handshake, creates paths with explicit local and remote tuples, labels ACKed transport bytes without claiming unique payload delivery, exports actual loss declarations including unreliable DATAGRAMs separately from retransmission counters, avoids zero-length null-pointer copies during initial ALPN, empty session-ticket setup, and bodiless stream FIN handling, and returns overflow-checked, `XQC_ALIGNMENT`-aligned large pool allocations. |

The mqvpn patch adds `src/spki_pin.c`, `src/spki_pin.h`,
`src/server_hardening.c`, `src/server_hardening.h`,
`tests/test_spki_pin.c`, `tests/test_server_hardening.c`, and
`tests/test_server_adversarial.c` as GPL-3.0-only files. Its changes to
existing Apache-2.0 upstream files preserve their upstream license and
notices.

The additional GPL-3.0-only `patches/volparossa-xquic-edt.patch`
(`21472637e2b8e48c16af835a10137a67f450e07b565bb87241aa3f8895452a80`)
retains bounded initial exploration (2 MiB ACKed per path, at most 8 MiB attempt
debt plus one packet), then selects by live delivery cost and congestion.
It does not continuously equalise historical path bytes. Outstanding bytes
without ACK progress add bounded overdue time to the delivery estimate after
the normal RTT/variance/peer ACK-delay allowance. This uses xquic's actual
ACK-progress timestamp, which resets on send-from-idle; it changes neither
congestion control nor path state and sends no extra packets. The exact
callback contract covers the previously tested black hole and the measured
warm stale-fast-LAN state from mixed-link run `34139658819`: 32 low-rate
selections use the live slower WAN, real ACK progress restores fast-path
selection, and idle or sole-writable paths remain usable. The new regression
fails with the previous patch and passes with this patch. This is deterministic
scheduler evidence, not a live failover or bandwidth acceptance claim.
The explicit, default-off `VMP_DEV_EDT_TRACE=1` fixture option emits at most
64 sparse `NATIVE_EDT_SAMPLE` lines per connection, from 10 seconds inclusive
to 20 seconds exclusive after the first non-startup application selection.
This is a scheduling-relative window, not an HTTP-response marker. Each line
contains at most eight eligible local path numbers, their existing EDT costs
and sendability, bounded-counter metric snapshots, and the selected path;
the total eligible count makes truncation visible. There are no endpoints,
connection identities, payloads, general debug logs, or selection changes.
The callback test covers default-off and exact option parsing, the window,
sample spacing/cap, unchanged costs/winner and a congestion-blocked candidate.
Upstream revisions and original licenses are unchanged.

No local patch is applied to lwIP or BoringSSL. The builder checks all patch
hashes, runs `git apply --check`, and applies them only to fresh
`git archive` exports. The locked source checkouts remain unchanged.

### Protocol baseline and source evidence

| Protocol | Audited upstream capability |
|---|---|
| RFC 9484 | mqvpn implements MASQUE CONNECT-IP |
| RFC 9297 | mqvpn carries HTTP Datagrams and their context handling |
| RFC 9221 | xquic supplies QUIC DATAGRAM transport |
| RFC 9114 | mqvpn/xquic supply the HTTP/3 association |
| draft-ietf-quic-multipath-21 | the pinned xquic fork implements dynamic multipath path creation and removal |

Source inspection also found genuine multipath APIs, dynamic path add/remove,
and switches that keep FEC, XOR, and duplication disabled. These are upstream
capabilities only. They do not prove that the required VOLPAROSSA
client-to-distinct-relay-to-exit datapath carries traffic.

### Verification evidence

The following checks passed against the exact lock and patches on Debian 13
amd64 on 2026-08-05:

- `verify-upstream.sh` accepted all commits, trees, origins, tags, gitlinks,
  clean worktrees, notice copies, and patch hashes.
- A clean source build compiled BoringSSL, xquic, patched mqvpn, and the native
  daemon. The patched mqvpn upstream suite passed 33 of 33 tests, including the
  added SPKI-pin test.
- The strict native parser, server, runtime, and Unix-socket suites passed 4 of
  4 tests with warnings treated as errors.
- An isolated Debug build compiled the daemon and all four tests with
  AddressSanitizer, LeakSanitizer, and UndefinedBehaviorSanitizer. All 4 of 4
  tests passed with leak detection and halt-on-error enabled.
- The sanitized daemon completed an exit-mode inherited-credential smoke test:
  its parent directory was mode `0700`, its socket was mode `0600`, and
  exact device/inode cleanup removed the socket on SIGINT.
- Valgrind 3.24 reported zero errors and zero live heap bytes/blocks for each
  of the four release test executables.
- The resulting amd64 PIE executable was
  `native/volparossa-mpquic/build/volparossa-mpquic`, SHA-256
  `2386040e4190f7f548c6cc1e86018d866325233d106c796c5cd5138f2ddbf75d`,
  with mqvpn, xquic, lwIP, and BoringSSL linked statically. Its exact
  `DT_NEEDED` entries were `libm.so.6`, `libstdc++.so.6`,
  `libgcc_s.so.1`, and `libc.so.6`.
- The CMake install contract placed a byte-identical mode-`0755` executable
  at `libexec/volparossa/volparossa-mpquic` under a temporary prefix.

The API-v2 change set separately passed the following checks on Debian 13
amd64 on 2026-08-06:

- `cargo fmt --package volparossa-quic -- --check`,
  `cargo clippy -p volparossa-quic --all-targets --all-features -- -D warnings`,
  and all 19 `volparossa-quic` tests.
- Warnings-as-errors builds of both the standalone native boundary and the
  daemon linked to the real pinned mqvpn/xquic source; each passed all 4 native
  CTest executables.
- An AddressSanitizer/UndefinedBehaviorSanitizer daemon build linked to the
  pinned native source; all 4 CTest executables passed.
- `verify-upstream.sh` accepted the exact Wintun header, README, MIT license
  copy, all other locked source and patch inputs, and the JSON lock parsed
  successfully.

The full pinned graph was rerun from fresh `git archive` exports on Debian 13
amd64 on 2026-08-13 with no network access:

- `verify-upstream.sh` accepted the exact commits, trees, tags, gitlinks,
  origins, licenses, notices, bundled files, and patch SHA-256 values.
- BoringSSL, xquic, mqvpn/lwIP, the VOLPAROSSA wrapper, and the daemon were all
  compiled and linked with AddressSanitizer and UndefinedBehaviorSanitizer,
  frame pointers, and no sanitizer suppressions. The verifier found ASan and
  UBSan references in every production archive and the final daemon.
- All 33 mqvpn/lwIP tests and all 4 VOLPAROSSA wrapper tests passed with leak
  detection and halt-on-error enabled.
- The real daemon process handled both SIGINT and SIGTERM within the bounded
  five-second shutdown gate, exited zero, and removed its mode-`0600` Unix
  socket. Both sanitizer logs were empty.

The superseded incompatible API-v3 boundary and final mqvpn
session-correlation, bounded TLS-identity ingestion, and zeroization patch were
previously verified on Debian 13 amd64 on 2026-08-14:

- `verify-upstream.sh` accepted the final mqvpn patch SHA-256
  `dfeffe71a9db187a700a078f0f9f427a57f7eb69bfae2ba1b974a556bd22719d`
  and every other locked source, license, notice, bundled file, and patch.
- A clean release build passed all 33 mqvpn/lwIP tests and all 4 bounded
  wrapper tests. The real mqvpn loopback used the bounded in-memory PEM API and
  completed its handshake after the sealed memfds had already been closed. It
  also correlated the client-originated inner packet with the connect/disconnect
  session ID; focused API tests covered bounds, interior NULs, transactional
  rejection, legacy replacement wiping, and malformed identity rejection.
- One clean, offline ASan+UBSan graph instrumented 350 BoringSSL, 156 xquic,
  145 mqvpn/lwIP, and 10 wrapper C/C++ compile commands, plus their production
  links. All 33 upstream and all 4 wrapper tests passed with leak detection,
  halt-on-error, abort-on-error, and no sanitizer suppressions.
- The sanitized daemon side-effect-free `--api-version` probe wrote exactly
  `3\n`; its SIGINT and SIGTERM lifecycle checks exited zero and removed the
  exact mode-`0600` control socket.
- Valgrind 3.24 reported zero errors, zero definitely/indirectly/possibly lost
  bytes, and only the three standard descriptors open for focused release API
  and server-loopback tests. The remaining 760 reachable bytes are three
  BoringSSL thread-local caches rather than lost allocations.
- `volparossa-quic` passed formatting, Clippy with warnings denied, and all 22
  superseded API-v3 unit tests.

That historical run does not claim the separate BoringSSL Go suite, the xquic
CUnit suite, or disposable-network-namespace dataplane acceptance.

The incompatible native API-v4 descriptor-adoption boundary was then verified
on Debian 13 amd64 on 2026-08-14:

- `verify-upstream.sh` again accepted the locked commits, trees, tags,
  gitlinks, origins, licenses, bundled files, and the unchanged mqvpn and xquic
  patch SHA-256 values.
- A pinned release build passed all 33 mqvpn/lwIP tests and all 5 bounded
  wrapper tests. The real daemon's side-effect-free `--api-version` probe
  wrote exactly `4\n`.
- Focused boundary tests covered exact-one-FD `AddPath`, zero-FD non-AddPath
  requests, missing/two/three/late descriptors, descriptor-bearing frame
  payloads, wrong SHA-256 bindings, `MSG_TRUNC`, `MSG_CTRUNC`, trailing and
  incomplete frames, total-deadline timeout, EOF, peer credentials, strict
  private-overlay tuples, socket revalidation, and descriptor ownership on every reject path.
- `volparossa-quic` passed formatting, Clippy with warnings denied, and all
  26 API-v4 unit tests, including consuming `OwnedFd` on local validation,
  transfer, native rejection, and timeout paths.
- A final clean, offline ASan+UBSan graph instrumented 350 BoringSSL, 156
  xquic, 145 mqvpn/lwIP, and 12 wrapper C/C++ compile commands; its audited
  production/test link counts were 1, 1, 32, and 6 respectively. All 33
  upstream and all 5 wrapper tests passed with leak detection and
  halt/abort-on-error enabled. The API probe and bounded SIGINT/SIGTERM daemon
  lifecycle checks also passed with no sanitizer finding.

This API-v4 run does not prove privileged-helper origin for a descriptor,
the separate BoringSSL Go suite, the xquic CUnit suite, or disposable-
network-namespace dataplane acceptance.

The native API-v5 exit-listener boundary was verified on Debian 13 amd64 on
2026-08-26:

- `verify-upstream.sh` accepted the exact locked commits, trees, tags,
  gitlinks, origins, licenses, bundled files, and patch SHA-256 values before
  the build started.
- A clean, offline full-graph build instrumented BoringSSL, xquic, mqvpn/lwIP,
  the VOLPAROSSA wrapper, and the final daemon with AddressSanitizer and
  UndefinedBehaviorSanitizer. All 33 mqvpn/lwIP tests and all 5 wrapper tests
  passed with leak detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free API-version probe wrote exactly
  `5\n`. Bounded SIGINT and SIGTERM lifecycle checks exited zero, removed the
  exact mode-`0600` control sockets they created, and produced no sanitizer
  finding.
- Focused API-v5 boundary tests cover independent Rust/C listener socket
  checks, operation-specific descriptor binding, fragmented stream assembly,
  rejection of missing, late, extra, or truncated ancillary data, timeout
  cleanup, and fail-closed dormant exit dispatch.

This API-v5 run does not prove trusted-helper descriptor provenance,
assigned-address or network-namespace state, cryptographic consistency of the
candidate TLS identity, the separate BoringSSL Go suite, the xquic CUnit
suite, or disposable-network-namespace dataplane acceptance.

The incompatible native API-v6 process-instance and request-correlation
boundary was verified on Debian 13 amd64 on 2026-08-26:

- `verify-upstream.sh` again accepted every locked commit, tree, tag, gitlink,
  origin, license, bundled file, and local patch SHA-256 before compilation.
- A newly replaced, offline full-graph build instrumented BoringSSL, xquic,
  mqvpn/lwIP, the VOLPAROSSA wrapper, and the final daemon with AddressSanitizer
  and UndefinedBehaviorSanitizer. All 33 mqvpn/lwIP and all 7 wrapper tests
  passed with leak detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free version probe wrote exactly `6\n`;
  bounded SIGINT and SIGTERM lifecycle checks exited zero, removed their exact
  mode-`0600` sockets, and produced no sanitizer finding.
- Focused Rust/C tests share canonical request and descriptor-binding goldens
  and cover role preflight, target/instance substitution, exact response
  digest, stale-instance without automatic retry, signed Start scope, bearer
  commitment recomputation, tunnel-assignment shape, descriptor ownership, and
  fail-closed dormant exit dispatch. Native tests additionally cover
  BOOTTIME/REALTIME admission, rollback/forward-jump/overflow behavior,
  bounded no-eviction reservation/finalize replay tombstones, same-pair exit
  consumption through the framed server boundary, and FD cleanup when request
  digest generation fails. Rust and C independently enforce the exact
  VOLPAROSSA tunnel pools and MTU; focused native tests additionally cover
  immutable retention, duplicate/conflict handling, secure wiping, minimum
  IP version/length shape plus MTU, client source/reverse-destination
  ownership, exact current-path projection with only retired CLOSED records,
  and typed terminal reverse-queue overflow.

This API-v6 run does not prove separate role service identity, trusted-helper
descriptor provenance, server-side product-pool allocation, uniqueness and
route-lifetime binding, assigned-address namespace state,
independent signed-bundle verification or durable/general-nonce replay
authority, cryptographic consistency of the candidate TLS identity, the
separate BoringSSL Go suite, the xquic CUnit suite, or disposable
network-namespace dataplane acceptance. The proven replay ledger is
process-local and the accepted wall lifetime is converted once to a
`CLOCK_BOOTTIME` deadline; neither claim supplies the missing production
verifier and affine handoff.

The current mqvpn connection/session hardening patch was then reverified from
fresh locked-tree exports on Debian 13 amd64 on 2026-08-26:

- `verify-upstream.sh` accepted every locked commit, tree, tag, gitlink,
  origin, license, bundled file, and the mqvpn patch SHA-256
  `4ce314d8eb539dc362359f7fb901b6a76c827126b3c7091ee9b04528f556dd34`;
  `git apply --check` also accepted the patch directly against mqvpn commit
  `607c0df921e2c23bae8bea21cb3c6f2acb2db275`.
- The ordinary patched mqvpn/lwIP suite passed all 35 tests. Its raw QUIC/H3
  adversarial test covers concurrent and sequential duplicate CONNECT-IP
  requests, rejected-stream ADDRESS_REQUEST bodies and Datagram IDs,
  owner-only close, request-close and connection-close teardown, mixed server
  destroy, pre-H3 `MaxClients` N/N+1 refusal plus capacity reuse, and
  app-admitted unsupported-ALPN cleanup plus capacity reuse through
  `cb_refuse`. Mutation checks proved both the owner-QSID and `cb_refuse`
  assertions fail when their respective production checks are removed.
- A fresh offline ASan+UBSan graph instrumented 350 BoringSSL, 156 xquic, 150
  mqvpn/lwIP, and 20 wrapper C/C++ compile commands; audited link counts were
  1, 1, 34, and 10. All 35 mqvpn/lwIP and all 9 wrapper tests passed with leak
  detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free API-v6 probe and bounded SIGINT and
  SIGTERM lifecycle checks passed and removed their exact mode-`0600` sockets.

This run proves the bounded upstream connection/session lifecycle and native
unit boundaries only. It does not hard-code VOLPAROSSA's separate
`MaxClients=1` product policy and does not prove helper provenance, a usable
exit lifecycle, the separate BoringSSL Go or xquic CUnit suites, or disposable
network-namespace dataplane acceptance.

This evidence proves reproducible source intake, compilation, and bounded
native behavior. It is not namespace dataplane acceptance.

### Mandatory unresolved findings

Native API version 6 preflights an exact client or exit role and a fresh instance
per process start, then target-binds each later operation and correlates every
response to its canonical request digest. It carries signed reservation/finalize
IDs, bearer commitment, certificate digest, and both native instances together
with route-scoped auth, TLS name, and short expiry. Native recomputes the bearer
commitment for both Start roles. Multipath-at-least-two remains distinct from
single-path general UDP, no mode silently downgrades, and no unsolicited frame
is sent. Native converts an accepted wall expiry once to BOOTTIME and keeps a
fixed 128-record, no-live-eviction process-local ledger that rejects exact
reservation/finalize replay and one-ID scope collisions; it does not verify the
signed bundle or retain replay state across restart. `AddPath` consumes one
request-bound UDP descriptor, enforces the fixed private IPv6 overlay, and
never creates or binds a path socket.
`StartExitSession` consumes one separately domain-bound listener-shaped
descriptor, carries exact overlay peer metadata and bounded unparsed TLS
candidate material, then closes the descriptor and fails closed while the exit
backend remains dormant. Versions 1 through 5 and future versions fail closed.
The process instance does not change the RFC 9484 zero Context ID for IP
Datagrams. The current same-UID socket and both SCM_RIGHTS bindings prove local
correlation only, not binary attestation, authentication against an untrusted
agent, or privileged-helper origin. The active client `AddPath` backend also
checks one same-session namespace cookie; `StartExitSession` has no namespace
or assigned-address provenance. The client backend now retains one exact
product-pool assignment, exposes it only after `ESTABLISHED`, rejects mutation,
and enforces inner source/reverse-destination ownership. No test yet proves
that a production exit configured that pool or that the helper installed it in
the same namespace.

The following required contracts and evidence remain unresolved:

1. separate client/exit service identities and role sockets, followed by
   production agent preflight and affine handoff into signed route setup;
2. trusted helper-origin, exact namespace, server-side product-pool allocation,
   uniqueness/lifetime binding and assigned-address proof for each client path
   and exit-listener descriptor;
3. a unique delivered-payload counter rather than ACKed transport bytes;
4. an operational exit backend with helper-to-native listener provenance,
   independent signed-reservation verification, preverified affine replay
   handoff, and cryptographic certificate/key/name/SPKI consistency over the
   in-message TLS material;
5. disposable-topology proof of the patched EDT scheduler over real relay paths;
6. disposable-topology proof that an exit-originated inner datagram traverses
   the native queue/poll boundary and reaches the Rust client;
7. end-to-end dynamic path removal and failover across real relay paths; and
8. disposable namespace evidence for at least two distinct data-carrying relay
   paths, bidirectional CONNECT-IP, loss-aware scheduling, privacy captures,
   disabled duplication/FEC, and unchanged host routes, firewall, and DNS.

The implementation fails closed at unsupported seams. No native MPQUIC
dataplane status item, including A06 or A07, may be checked until the
applicable runtime gates and the real namespace acceptance suite are complete.

## Rust dependency audit

Rust dependencies are resolved by `Cargo.lock`. A complete
distributable notice inventory is declared only after the release lock passes:

```sh
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
```

`deny.toml` rejects unknown registries, unknown Git sources, wildcard
versions, yanked crates, and licenses outside its explicit allowlist. That
automated result and the license files embedded in resolved crates are
authoritative for a packaged release. Candidate packaging records each
package, version, license, and source and copies every crate's top-level
license/NOTICE files; it fails on an unapproved source or missing notice.

### Debian 13 compatible Rust security overrides

Four crates.io packages are overridden with verified project-local source.
The Hickory and time fixed releases require Rust 1.88, while the future
single-backend libp2p-yamux release also raises its MSRV above Debian 13's
Rust 1.85:

| Component | Exact source and upstream revision | License | Local security patch |
|---|---|---|---|
| hickory-proto 0.25.2 | crates.io SHA-256 `f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502`; git `527c9f470a418cf6b92da902ea0aaa5749963d59` | Apache-2.0 OR MIT; original license files preserved | `third_party/rust/patches/hickory-proto-0.25.2-rustsec.patch`, SHA-256 `bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a`; bounds compression candidates, rejects cross-zone NSEC3 proofs, and adds a non-default regression-only adapter |
| hickory-resolver 0.25.2 | crates.io SHA-256 `dc62a9a99b0bfb44d2ab95a7208ac952d31060efc16241c87eaf36406fecf87a`; git `527c9f470a418cf6b92da902ea0aaa5749963d59` | MIT OR Apache-2.0; original license files preserved | `third_party/rust/patches/hickory-resolver-0.25.2-dnssec.patch`, SHA-256 `2e070665e78337e620dfb3f8c15ff09a938ad3fa711e240798732de4c204f1b2`; rejects bogus answers before cache insertion and CNAME following; the archive's non-authoritative development lock is omitted from the vendor tree |
| time 0.3.41 | crates.io SHA-256 `8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40`; git `cc35dcfcde917bb833c114e2b4c00292a374c4ba` | Apache-2.0 OR MIT; original license files preserved | `third_party/rust/patches/time-0.3.41-rustsec.patch`, SHA-256 `bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a`; bounds RFC 2822 comment recursion |
| libp2p-yamux 0.47.0 | crates.io SHA-256 `f15df094914eb4af272acf9adaa9e287baa269943f32ea348ba29cfb9bfc60d8`; git `9736aacf814eb7b9df0372c5f9adcffba8a4b212` | MIT; exact upstream repository license retained | `third_party/rust/patches/libp2p-yamux-0.47.0-single-backend.patch`, SHA-256 `1a845f6cfaa57c993b54f654dc8e9294a450de8c46be323618481a7cc750740d`; removes the retired 0.12 backend, pins fixed yamux 0.13.10, and preserves read-after-close policy |

The complete sources, patch review notes, resulting tree hashes, test
contract, and removal condition are in `third_party/rust/README.md`.
`scripts/check-rust-dependencies.sh` reconstructs all four trees from the exact
archives, applies the locked patches, byte-compares the result, verifies
unchanged licenses and the feature graph, runs CVSS 4.0-capable cargo-deny
advisory/license/ban/source checks, and performs an independent no-fetch cargo-audit scan against a
local RustSec checkout. It prints that checkout's exact commit.

The GPL-3.0-only harness under `third_party/rust/backport-regressions` has a
Rust-1.85-targeted lockfile (SHA-256
`965c606acf0c93d9a9d6b8415b3ae503185e8b3ec7eecf3d6251c9047cd14659`)
and executes the dependency-security regressions offline. Its Hickory feature calls the same
private NSEC3 validator through a doc-hidden adapter; that feature is absent
from and forbidden in the production dependency graph. Its bounded Yamux raw
frame test proves an oversized first-stream body fails closed without an
unwind; its public-wrapper test preserves `set_max_num_streams` and
`read_after_close(false)` semantics.

The resolver-specific check rejects DNSSEC-bogus answers before cache insertion
and alias following, backporting upstream commit
`92f93c0b889f6a292bc943304d88c4c6561fe1b9` for GHSA-5j98-2g5x-46v6.
The separate CNAME advisory GHSA-6f2x-v7q7-m7m5 is assessed against the pinned
0.25 stub and the absence of the separate recursor crate in both graphs, with
targeted regression and graph checks. Neither GHSA receives a new scanner waiver.

RustSec scanners still identify the unchanged semantic versions as affected.
`RUSTSEC-2026-0009`, `RUSTSEC-2026-0118`, and
`RUSTSEC-2026-0119` are narrowly exempted only after reconstruction
establishes the local fixes. These are locally remediated advisory-version
matches, not accepted vulnerable upstream artifacts. The bounded positive
A/AAAA DNS-proof resolver explicitly enables the existing `dnssec-ring`
backend; its feature guard still forbids the unused aws-lc backend and the
regression-only adapter. The NSEC3 fix and its isolated regression remain
mandatory, and no vendor source, root-anchor, or license bytes are changed.
The standalone fuzz graph, which does not include this UDP resolver, still
excludes both DNSSEC backends.

The dependency gate requires CVSS 4.0-capable `cargo-deny >= 0.18.6` and
`cargo-audit >= 0.22.1`; the former runs all four checks while the latter
provides an independent advisory scan.

Candidate packaging excludes workspace members and admits path dependencies
only at the four exact verified vendor paths above.
`yamux 0.13.10` omits license files from its crate archive, so exact
Apache-2.0 and MIT files from official release tag
`70db05dc63e8368bd0559a5ec0dba6e5fc2bdd41` are retained under
`third_party/rust/licenses/yamux-0.13.10/`. The collector fallback requires the
exact registry package identity, license expression, and embedded VCS
revision. `packaging/test-collect-cargo-licenses.sh` proves every vendored and
fallback license is collected and an arbitrary non-workspace path dependency
is rejected.

## Notable Rust source dependencies

### Private Unbound system-library integration

The original GPL-3.0-only shim in `native/volparossa-dns-worker` dynamically links
Debian's `libunbound8`; it does not vendor or silently download an executable.
Reviewed upstream is [NLnet Labs Unbound](https://github.com/NLnetLabs/unbound/tree/13b6717f1716810523ffb60f971a6c9c5e8ce127),
release `1.26.1`, exact commit `13b6717f1716810523ffb60f971a6c9c5e8ce127`
(signed tag object `343a5b81f9803199364f440ebe2fc3195efda25d`). The upstream
[BSD-3-Clause license](https://github.com/NLnetLabs/unbound/blob/13b6717f1716810523ffb60f971a6c9c5e8ce127/LICENSE)
and distribution notices remain unchanged. Installed Debian dependencies retain
their complete copyright/license inventory under `/usr/share/doc/libunbound8/`.
No local patch to libunbound is applied; Debian packaging/security patches are
not misrepresented as byte-identical upstream source.

The initial workspace-only ABI build uses authenticated Debian 13 security
package metadata, version `1.26.1-0+deb13u1`, amd64:

| Package | SHA-256 |
|---|---|
| `libunbound8`, 643372 bytes | `2331c4c305f68aab91dbe16245bd76c0e0edc532353b3ce52accad71d24dfbb3` |
| `libunbound-dev`, 213572 bytes | `e909714ea6d39833cf42e8e48f3dbe68a42147d8853850e7848769d7fd5a3d12` |

Both were checked before extraction into ignored `build/native-unbound-deps/`;
nothing was installed into the development host. Source provenance is available
from the [Debian package](https://packages.debian.org/trixie/libunbound8).
Runtime transitive system dependencies are libc6, libevent and OpenSSL;
`dns-root-data` supplies read-only root hints/anchors and retains its own notices.
The package does not depend on or start the standalone Unbound daemon.

### Rust dependency families

| Component family | Purpose | Upstream license expression to verify in release audit |
|---|---|---|
| Tokio, tracing, futures | async runtime and structured diagnostics | MIT |
| serde, serde_json, serde_yaml, prost | configuration and wire encoding | MIT or Apache-2.0/MIT |
| rust-libp2p and Quinn | decentralised control plane and QUIC | MIT |
| rustls, ring, ed25519-dalek, x25519-dalek, Argon2 | transport, identity, and key protection | mixed permissive licenses; inspect every resolved crate |
| `hpke` 0.14.1 (`rust-hpke`) | RFC 9180 route-credential sealing, exact crates.io pin in `Cargo.lock` | MIT/Apache-2.0; upstream `https://github.com/rozbb/rust-hpke` |
| rusqlite and SQLite bundle | bounded local peer/session state | MIT for wrapper; SQLite is public domain |
| rtnetlink, netlink-sys, wireguard-uapi, nix, libc | Linux networking and OS boundary | mixed permissive licenses; inspect every resolved crate |

This table is descriptive rather than a claim that every transitive Rust
dependency has already been approved. Never replace the native provenance
record with an unverified version tag or a downloaded executable.

## Development-only audit-tool cache action

Quality uses the separate `restore` and `save` entrypoints of
[actions/cache v6.1.0](https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9),
pinned to `55cc8345863c7cc4c66a329aec7e433d2d1c52a9`. Origin:
`https://github.com/actions/cache`; license:
[MIT, unchanged upstream notice](https://github.com/actions/cache/blob/55cc8345863c7cc4c66a329aec7e433d2d1c52a9/LICENSE).
There are no local upstream patches or vendored action binaries. This is external
CI tooling, not a VOLPAROSSA runtime dependency. Only this workflow's checked,
source-built `cargo-deny 0.18.6` and `cargo-audit 0.22.1` are cached; their build
versions, locked upstream dependencies and audit/license obligations are retained.


## Silex Studio baseline research (2026-10-22; no source imported)

- Origin: https://github.com/silexlabs/Silex
- Selected release: v3.9.0; exact commit `672efed69dda04c0a1e968859239e042f00d9538`.
- Inspected editor/Node server and Rust `silex-server` source notices:
  AGPL-3.0-or-later; root package uses the shorthand AGPL-3.0.
- Desktop Tauri metadata differs by source: `desktop/src-tauri/Cargo.toml` declares
  AGPL-3.0-or-later; `desktop/src-tauri/src/main.rs` has a GNU GPL version 3-or-later
  source header. A separate GPL file is present. Preserve both source observations
  without collapsing the manifest and header to one identifier.
- The pre-existing Studio GPLv3 license file is preserved. Do not use it to
  relabel upstream AGPL components or infer fulfilled network-service/source obligations.
- No downloaded executable, vendored source, local patch or build was part of this
  research entry. Studio's `upstream.lock.json` binds reviewed file blobs. A later
  bounded hosted fixture built and ran the pinned source; full dependency audit and
  complete Studio acceptance remain open (see [Studio hosting](docs/services/STUDIO_HOSTING.md#current-bounded-runtime-evidence--2026-10-23)).
  Preserve notices and record any future patches, distribution/network-source
  obligations and asset licenses before activation.
- Primary files and adapter/telemetry/update boundaries are linked in
  [Studio hosting](docs/services/STUDIO_HOSTING.md#silex-source-selection-and-interfaces).
