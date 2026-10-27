# Protected compute: public verifier fixtures

This guide describes the supported public verifier profile and software quote
flow. Recorded public-fixture success is compatibility evidence, **not protected
remote execution**. The core must verify another node's execution environment
before releasing private task context. The existing local private service and
public peer-task admission retain their own authority boundaries. Consult
[implementation status](../IMPLEMENTATION_STATUS.md) for current source-bound
results; the recorded software trials do not supply confidential-hardware or
two-node private-workload acceptance.

## What this trial checks

The [hosted workflow](../../.github/workflows/protected-compute-verifier.yml)
builds the upstream Rust `virtee/sev` library at exact commit
`a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5`, using Rust 1.85.0 and the
explicit lockfile correction below. It enables only `snp,crypto_nossl`, with
default features disabled.
The selected upstream test target executes four public Milan fixtures:

- Verify the supplied AMD SNP certificate chain.
- Reject a tampered chain.
- Verify the supplied signed attestation report.
- Reject a tampered report.

These are upstream public samples, not newly generated hardware reports or
VOLPAROSSA users' data. No `/dev/sev` device, private model, task input or secret is
used. This standalone upstream trial supplies no production admission backend;
the separately tested core integration is described below.

The [pinset](../../tests/integration/protected-compute-verifier-pins.json)
records the exact source tree, nine original file hashes, and the corrected
lockfile identity. The trial requires pristine upstream before applying the
correction. Subsequent checks accept only that exact unstaged lockfile change,
verify the original `HEAD:Cargo.lock` separately, and reject other tracked,
staged, untracked or ignored files and mode changes. Dependency acquisition
is separate from offline Cargo execution;
`--offline` is not an operating-system network sandbox.

## Exact lockfile correction

The pinned upstream [lockfile](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/Cargo.lock#L965)
contains one dangling dependency reference: `num-bigint-dig 0.8.6` still names
`rand 0.8.5`, although the [same commit](https://github.com/virtee/sev/commit/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5)
replaces that package with `rand 0.8.8`. The fixture changes only that reference
to the already pinned `0.8.8`; it changes no package version, checksum, manifest,
source or test. Cargo never regenerates the lockfile, and both acquisition and
test commands retain `--locked`.

Both original and effective files contain 66,223 bytes. Their SHA-256 values are:

- Upstream: `fe1511ef932c1a54d0cd70ac470b41de8357ab2efca9ed6b3a4ea22c3b7d3bd0`.
- Effective: `7b7dbf853cecf44a8d2a6b51283012b446db97600f4e19af36a1c642b8bfa7cb`.

The schema-two pinset and result receipt distinguish these identities and name
the exact one-occurrence correction. The immutable Git commit and tree continue
to identify upstream, not an unmodified effective checkout. Preparation writes
no success receipt and cannot substitute for cryptographic tests.

## Evidence and limits

Only a zero-exit run with all four named tests executed and passed can produce a
success receipt. Missing, ignored, duplicate or extra test lines are rejected.
The original bounded log, both pipeline exit statuses and compiler-version
outputs are retained separately. Log overflow fails the trial; an earlier
success receipt cannot be overwritten by a new execution.

The source-bound public fixture and follow-up software runs are indexed in
[implementation status](../IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation).
Their original revisions, positive/negative test counts, failed attempts, artifact
digests and timing observations remain in the
[development archive](../archive/development-notes-20261026.txt). Fixture compilation
or execution timing is not remote-task performance evidence.

Inert harness controls use synthetic output, small text-only Git repositories
and harmless shell functions; they cannot substitute for the four actual
cryptographic tests or authorize worker admission.

This passing run establishes compatibility with the selected public fixtures,
not a trustworthy worker or confidential task.

## Core integration

The [core module](../../crates/volparossa-content/src/provider/compute/attestation.rs)
verifies exact received report bytes and binds a fresh finite owner challenge to
a proposed session key. Public signature fixtures and synthetic session-state
checks do not prove that a guest possesses that key or can execute a private task.

The [core workflow](../../.github/workflows/protected-compute-admission.yml)
fetches with `--locked`, requires its committed source/lockfile to remain unchanged,
checks the actual resolved features and runs tests offline. Receipt schemas
retain the distinction between fixed-lock verification and historical dependency
resolution; broader workspace integration is a separate gate.

The public-key-only use of the RSA dependency has an explicit, mechanically
checked [advisory scope](../../THIRD_PARTY_LICENSES.md#rsa-advisory-scope);
it is not treated as a patched general-purpose private-key implementation.

## Binding endorsement claims to the report

The integrated core checks the signed VCEK's product, chip identifier and
firmware-version extensions against the exact report before returning signature
facts. It compares each component of `REPORTED_TCB`, not the current, committed
or launch TCB. The existing certificate-size bound, pinned reference chain and
cryptographic verification remain unchanged.

The parser follows [AMD KDS specification 57230 revision 1.05, section 3.1](https://docs.amd.com/api/khub/documents/U5H~LHvkigTowyppBkpyrA/content):
canonical integers and IA5 product text, a raw 64-byte hardware identifier, zero
reserved components, and the documented component ranges. The
supported leaf profile is intentionally narrower: exactly eleven known,
noncritical AMD extensions. Additional extensions and other report/product
profiles need separate review. A version-two report cannot establish a CPUID
stepping comparison.

Regression coverage includes valid public evidence, incomplete/duplicate
extensions, encoding/range errors, identity/component mismatches and refusal to
bypass actual signatures. Synthetic certificate edits test consistency, not
authentication. This binding supplies neither private-input release nor worker
admission; the outstanding appraisal obligations remain explicit below.

## Checking certificate algorithm declarations

The integrated verifier checks the fixed Milan chain's algorithm declarations after
actual cryptographic verification and before returning signature facts. Both
signature identifiers must agree and name the supported PSS profile: SHA-384,
MGF1/SHA-384, a 48-byte salt and trailer 1. The VCEK must declare a P-384 EC key
with a byte-aligned, uncompressed point. Existing cryptographic verification,
not a point-shape check, establishes the valid public key and signatures.

This follows [AMD 57230 revision 1.05, tables 7–9](https://docs.amd.com/api/khub/documents/U5H~LHvkigTowyppBkpyrA/content),
[RFC 5280's signature-identifier agreement](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2),
[RFC 4055's hash and PSS parameters](https://datatracker.ietf.org/doc/html/rfc4055#section-3)
and [RFC 5480's EC key identifiers](https://datatracker.ietf.org/doc/html/rfc5480#section-2).
Absent and NULL SHA-384 parameters are supported. Trailer 1 may be omitted or
explicit, as in the public AMD fixture; other values are rejected. Unknown,
duplicate, reordered, implicit or trailing fields do not extend this profile.

Real API-negative cases retain original signed certificate bytes/signatures
while changing the outer algorithm declaration. Separate synthetic structures
exercise malformed parameters and key encodings; they authenticate nothing.
Receipt schemas keep the named test set distinct and historical schemas
replayable. The original Clippy-failed run and its corrected follow-up remain
separate source-bound results in the
[development archive](../archive/development-notes-20261026.txt).

These checks do not establish a complete general-purpose certificate path or
live datapath. Dependencies, features, appraisal obligations and execution
permissions do not expand merely because a public-fixture test passes.

## Supplied certificate path and revocation checks

Merged PR242 makes the supplied Milan ARK revocation list a mandatory
input to `PendingSession::verify_and_bind`. It checks the fixed legacy
ARK–ASK–VCEK path: issuer names, CA constraints, signing usage, supported
extensions, key identifiers and certificate validity. It is a closed Milan
profile, not a general-purpose X.509 validator.

The pinned ASK's signed KeyUsage bytes are `03020104`: certificate signing
with an extra zero named bit. Re-encoding the decoded flags produces
`03020204`, so byte equality after re-encoding would reject this vendor
certificate. The closed legacy profile requires the original ASK bytes (and
ARK `03020106`) plus their exact decoded rights. It does not admit arbitrary
padding, additional rights or normalized replacement certificates. Other
extensions retain canonical decoding; actual chain signatures remain required.

The bounded, canonical DER revocation list must have a valid ARK signature and
cover the path's ASK. Unsupported scope, delta lists, malformed entries,
revocation and invalid time windows reject the attempt. Its actual
PSS/SHA-384 signature is checked with the already pinned `rsa =0.9.10`, now
also a direct dependency; no package version changes. The public-key-only
advisory guard covers this second verification path.

Session binding rechecks time and cancellation after cryptographic work. The
result expires at the earliest challenge deadline, certificate expiry or CRL
`nextUpdate`; supplying collateral never renews an owner's authority. A bound
result still leaves four explicit obligations: authorized production roots,
individual VCEK status and collateral freshness, vendor TCB/local policy, and
authorized workload/key origin. A valid ASK-scope list is not proof that a VCEK
is unrevoked or that no newer vendor information exists.

The public AMD CRL fixture's real signature verifies independently with
OpenSSL. Regressions cover tampering, path/scope refusal, revocation entries,
finite session binding and the pinned ASK KeyUsage normalization boundary.
Synthetic negative certificates/session facts authenticate no worker.
Source/lock-bound receipt schemas retain historical replay without treating
synthetic cases as hardware acceptance.

The original Endorsement-failed trial and subsequent corrected positive path
are retained with their exact source/tree/artifact and Quality/CodeQL results in
the [development archive](../archive/development-notes-20261026.txt). A later
software pass does not overwrite that failure or establish a protected worker.

See [the collateral provenance](../../THIRD_PARTY_LICENSES.md#supplied-milan-revocation-list)
for the fixture's exact digest, issuer and validity window. This change adds no
collateral downloader, protected worker, admission permit or private-input
release. The hardware trial below remains required.

## Explicit owner local policy

`LocalPolicy` supplies immutable expectations to `SessionOwner`: an exact
public measurement, minimum guest SVN, four independently selected TCB minima
and an explicit SMT choice. There are no production defaults. Every minimum
contains bootloader, TEE, SNP and microcode components; each component must meet
its own floor. A larger earlier component cannot compensate for a smaller later
one. Debug and migration-agent permission remain forbidden. Source-bound
local-policy proof is indexed in
[implementation status](../IMPLEMENTATION_STATUS.md#explicit-local-policy-for-protected-compute);
it is not a protected worker or current vendor-security decision.

The supported Milan report fields are distinct:

| Signed field | Offset | Local comparison |
| --- | --- | --- |
| `CURRENT_TCB` | `0x38` | Explicit running-firmware floor |
| `REPORTED_TCB` | `0x180` | Explicit reported floor; existing VCEK binding still applies |
| `COMMITTED_TCB` | `0x1e0` | Explicit committed-firmware floor |
| `LAUNCH_TCB` | `0x1f0` | Explicit launch/import floor |
| `POLICY.SMT` | Policy bit 16 | Whether the guest permits SMT |
| `PLATFORM_INFO.SMT_EN` | Platform bit 0 | Whether SMT is actually enabled |

The legacy TCB layout uses bytes 0, 1, 6 and 7 for those four components;
bytes 2–5 are reserved. Provisional current firmware, committed firmware and
the reported version used for VCEK derivation need not be equal. See
[AMD ABI 56860 revision 1.59, §§2.3, 3.3–3.4, 4.3 and 7.3](https://docs.amd.com/api/khub/documents/NJQrpYY7KZGtlxDEdBGtzA/content).
Bootloader, TEE and SNP values are limited to 0–127; microcode uses 0–255,
following [AMD KDS 57230 revision 1.05, §4.1 table 13](https://docs.amd.com/api/khub/documents/U5H~LHvkigTowyppBkpyrA/content).
`RequireDisabled` rejects either SMT permission or actual SMT enablement;
`Allow` is an explicit local choice, not a mitigation claim.

Challenge version 2 uses binding domain
`VOLPAROSSA/SNP-MILAN-V2/SESSION-EVIDENCE/2\0`. Canonical protobuf fields bind
measurement and minimum guest SVN. A required 18-byte field binds restriction
encoding version 1, the four TCB floors in current/reported/committed/launch
order, and the closed SMT discriminant. The unchanged public policy identifier
is only an identifier: changing any local expectation changes `REPORT_DATA`.
Version-one, missing, unknown, out-of-range and noncanonical policy encodings
reject rather than inherit defaults. No challenge, attempt or collateral expiry
is extended, and policy rejection consumes its attempt.

The unchanged public signed report has TCB components `(3, 0, 8, 115)` at all
four stages and permits/enables SMT. Its positive comparison is fixture-only.
Raised-floor regressions compare that same authentic report against every
stage/component separately; other policy/session mutations are synthetic,
not new hardware reports. Receipt validation retains exact source/lock binding,
named tests and historical-schema separation.

Numeric floors cannot establish current platform security.
[AMD-SB-3015](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3015.html)
uses `ALIAS_CHECK_COMPLETE` at platform bit 5 to report its mitigation; the
unchanged closed v2 profile does not admit that bit.
[AMD-SB-3016](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3016.html)
also requires OS changes and guest reinitialization, which these legacy report
comparisons do not establish. Separately, the authors of
[Insecure Despite Proven Updated](https://arxiv.org/abs/2605.12990) report
software-only extraction of a Milan root VCEK seed and forged reports. That
research reinforces the architectural limit: accepting larger signed numbers
is not independent evidence of trustworthy report-key provenance.

All four bound-evidence obligations remain: production root authorization,
individual VCEK status and collateral freshness, current vendor security/TCB
appraisal beyond these local comparisons, and authorized workload/key origin.
This implementation adds no report-version fallback, root authority, network call,
worker permit or private-input release. A current vendor mitigation appraisal
and the real protected-worker trial remain separate requirements.

## Guest-side session candidate

The `provider::compute::guest` module implements the other side of this
challenge protocol. Its source-bound software lifecycle tests do not admit a
private worker or provide a firmware/two-node private-task hardware trial.

A `GuestSessionOwner` has an explicit expiry, a finite attempt budget and at most
one active session. It accepts only the existing canonical version-two challenge,
checks wall-clock and monotonic deadlines, rejects reuse, and generates its own
ephemeral recipient key. There is no imported private-key parameter or private-key
export. This is **process-owned key material**, not proof that a hypervisor or
device administrator cannot read it; that requires an approved measured guest
and actual confidential-computing verification.

The production quote operation opens the fixed Linux `/dev/sev-guest` device
through the already pinned upstream library. It calls `SNP_GET_REPORT` with the
challenge-and-key-bound `REPORT_DATA`, message version one and VMPL zero. Message
version is not report version: the received report must actually be the supported
1,184-byte version-two format. Unsupported versions, lengths, VMPL values or
bindings reject without rewriting the signed bytes or inventing a fallback.
The operation fetches no certificates and accepts no caller-supplied device path.

Cancellation erases the owned key even while a firmware call is in progress. A
blocking ioctl is not claimed to be interruptible: its session slot stays occupied
until the call returns and is joined by its caller. Dropping the session also
erases the key; expiry is enforced at the next operation or drop, not by a hidden
timer. Quote responses expose only public report and binding data. Receiving such
a response does not create verified evidence, task authority or permission to
release private input. Raw reports can contain hardware identifiers and must not
be logged, publicly cached or published as routine diagnostics.

Software lifecycle coverage includes canonical request/response bounds,
fresh keys, replay/attempt limits, cancellation during collection, expiry,
report rejection and separation from the real verifier. Positive collection
uses an explicitly test-only synthetic source; production uses firmware only.
Receipts retain source/lock binding and joined command processes. Neither
software success nor a compiled firmware call proves execution inside an
approved confidential guest; original failures and artifacts remain in the
[development archive](../archive/development-notes-20261026.txt).

The integrated quote-only service below connects an authorized caller to this
module over the existing protected provider stream. An approved guest image and
model/runtime assets, full report appraisal and protected task-input/output
handling remain required. The guest module itself installs no daemon, changes no
host configuration and starts no listener or scheduler. A compiled firmware call
does not enable private work.

Source references: the pinned [firmware API](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/src/firmware/guest/mod.rs)
and the [Linux SEV guest interface](https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html).

## Authorized quote exchange candidate

The integrated quote-only service and CLI exercise the existing protected
stream without admitting a worker or sending a private task. Recorded software
checks cover appraisal, guest lifecycle, quote handling and typed agent/control/
CLI integration. Original source/lock bindings, artifacts and failed attempts
remain in the [development archive](../archive/development-notes-20261026.txt).
Production-route and confidential-hardware acceptance remain separate gates.

### Operator authority and cancellation

`volparossa compute quote attach` uses the existing protected local control
socket. It requires `--bind`, `--advertised-hostname`, `--requester-key`,
`--max-seconds` and `--max-attempts`; none grants general peer access. The exact
requester key must be valid and nonzero. The grant permits at most 600 seconds
and 64 attempts, while each quote retains the existing shorter challenge limit.
Current participation, endpoint policy and service registration are checked
again during operation. Public compute and quote registration remain separate.

`volparossa compute quote detach` revokes the grant and retained keys. A live
supervisor also revokes them on expiry or authority loss. Guest sessions own
their state without exporting private keys; dropping their owner cancels any
surviving session. A process-wide single permit stays with the blocking firmware
worker until its real return, even if its async supervisor has been cancelled.
Detach therefore does not promise an interrupted ioctl or immediate free capacity.

### One fresh protected exchange

`volparossa compute quote verify` requires `--provider-key`, `--public-policy`,
`--vcek` and `--vendor-crl`. The public policy is strict JSON, bounded to 4 KiB,
with explicit version, public policy identifier, measurement, guest SVN,
current/reported/committed/launch TCB floors and SMT choice. It supplies no
production root override or private task context. The bounded DER certificate
and CRL are supplied locally; this command does not fetch collateral.

The agent opens the existing protected route, checks the selected provider's
offer and pinned TLS identity, and receives its signed quote challenge. Only
then does it tell the CLI that the stream is ready. The CLI creates its fresh
30-second, one-use verifier session after that readiness response, so route setup
does not consume the verifier's short challenge lifetime.

Provider selector 7 and signing domain `VOLPAROSSA/compute-quote/v1\0` are distinct
from public compute selector 5 and its unchanged domain. Bounded binary frames
travel over the same owned connection, not a transcript file or a new unprotected
listener. The response binds the exact request and guest-generated public key.
Transport closure and a final route/policy check precede reference verification.

The CLI prints only closed evidence status and the outstanding appraisal
obligations. It never prints a raw report, hardware identifier, key or transcript.
Reference verification keeps `complete_appraisal`, `worker_admission` and
`private_input_released` false. The receiving authorized requester necessarily
processes the report in memory; this exchange is not anonymous quote disclosure.

### Software evidence and remaining route proof

Regressions cover message separation, exact authorization, bounded framing,
retained-key expiry, delivery failure, cancellation during firmware work, late
results, policy loss, finite attempts and typed agent/control/CLI policy/output.
Synthetic firmware is test-only and cannot be selected in production config.

The quote software receipt requires the original source/lock binding and its
named appraisal, guest and quote test sets. These do not establish production-route
execution, confidential hardware, complete appraisal or private-task execution.
[Implementation status](../IMPLEMENTATION_STATUS.md#authorized-quote-exchange-candidate)
tracks those boundaries separately. An authenticated device-refusal candidate
cannot turn lack of attestation into permission for private work.

### Explicit key confirmation

The separate `--key-confirmation-v1` flag on both `volparossa compute quote attach`
and `volparossa compute quote verify` selects same-connection key confirmation.
The legacy profile above remains the default. An enabled requester rejects an
unsupported profile or mismatched readiness response; it does not fall back to
the legacy exchange. Existing finite requester authority, policy checks and
collateral inputs still apply.

The CLI independently verifies the original signed quote and keeps its verifier
owner alive while generating a fresh random 32-byte probe. The pinned HPKE
implementation encrypts that probe for the proposed session key. Its context
binds the provider, requester, original signed challenge and request, quote,
session key and effective expiry. The provider handles one probe on the same
connection; the CLI checks the correlated signed echo before accepting the
final local acknowledgement. Setup and frame exchanges cannot renew the original
deadlines. Cancellation, expiry, authority loss and dropped work release or
cancel the same owners; the firmware worker retains its permit until it joins.

This command accepts no private task plaintext and returns no reusable worker
permit. Successful output is version 3 with `key_confirmation=true`, while
`complete_appraisal`, `worker_admission` and `private_input_released` remain false.
It proves possession within this exchange, not that the key originated in an
approved confidential guest. Authenticated device-unavailable refusal retains
its separate conservative result. Raw reports, keys and transcripts are not
printed or made public.

The key-confirmation software result retains its exact source and synthetic
firmware scope in the [development archive](../archive/development-notes-20261026.txt).
Full integration and suitable-hardware trials remain separate open acceptance
requirements.

## What is still needed before private tasks can run remotely

Certificate and report signatures are necessary but insufficient. A complete
worker-admission path still needs:

- Independently authorized trust roots, certificate and revocation handling,
  approved guest measurements, security-version requirements and debug policy.
- A fresh client challenge bound to the approved guest's session key and the
  particular task, with replay rejection and finite execution authority.
- Verification of the exact received report format and signed bytes. The guest
  must also verify authorized model/runtime assets before using task keys.
- Protected input, execution and output, plus cancellation, resource limits and
  cleanup under the same core-managed task lifecycle.
- An actual two-node trial on suitable confidential-computing hardware,
  including failed attestation and refusal to release private input.

The fixture's supplied self-signed root is not independently granted production
authority. The supported path and ASK-scope CRL checks do not establish current
individual VCEK status, an approved workload or newest-collateral freshness.
These remaining checks must not be replaced by a peer signature, encrypted
transport or agent approval.

Source references: [upstream fixture tests](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/tests/certs.rs),
[chain verification](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/src/certs/snp/chain.rs)
and [crate configuration](https://github.com/virtee/sev/blob/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5/Cargo.toml).
See [third-party provenance](../../THIRD_PARTY_LICENSES.md#public-snp-verifier-fixture-trial)
and the [implementation ledger](../IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation).
