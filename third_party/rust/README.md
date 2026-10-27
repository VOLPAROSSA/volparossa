# Reviewed Rust dependency security changes

## Current F04 source candidate: fixed P-384 arithmetic, 27 October 2026

The source candidate retains pinned Rust 1.99.1 and zbus 6.1.0. Its new
`RUSTSEC-2026-0387` remediation uses the original SEV 8.0.0 Git source with
three bounded API adaptations, `p384 0.14.0`, and fixed `crypto-bigint 0.7.9`.
The lockfile resolution and actual cryptographic/compiler/codegen evidence
remain pending; source reconstruction is not security or runtime acceptance.
No exception is added for that advisory. The older sections below retain the
original backport provenance and historical Rust-1.85 compatibility evidence.

`crypto-bigint 0.5.5` is reached only through `elliptic-curve 0.13.8` under
SEV's P-384 dependency. That semver line cannot select the fixed 0.7 release.
RustSec's patched minimum is 0.7.6; crates.io marks 0.7.6, 0.7.7 and 0.7.8
yanked. The selected 0.7.9 is the smallest currently non-yanked patched release
and requires `ctutils ^0.4.5`. The exact graph guard requires one registry
`p384 0.14.0`, `ecdsa 0.17.0`, `elliptic-curve 0.14.3`, `primeorder 0.14.0`
and `crypto-bigint 0.7.9`, plus one unmodified path `ctutils 0.4.5` in both
root and fuzz. It rejects duplicate/legacy versions and expansion of SEV into
the fuzz graph. The graph must be established by real hosted Cargo resolution.

### SEV source and bounded adapter

The original Git revision is `a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5`, tree
`636379a232b75ad3c0f2a079acc1788dc13a920f`. The GitHub Git-commit API and
the retained local Git object agree on that tree. A deterministic `git archive`
with prefix `sev-8.0.0/`, gzip timestamp zero, is retained as
`sources/sev-8.0.0-a966d06.tar.gz`, SHA-256
`6fa9d33543b5ea51b153d2fbe01111eba821f4dc92a7949d83056b2d947eb2b5`.
This is a locally generated archive of the exact official Git tree, not a
crates.io archive or a claim of upstream signature verification.

`patches/sev-8.0.0-p384-0.14.patch`, SHA-256
`2ce121d7fb50f2d31a3da3eaa4ebf260e6a588a4c2749693fd155d975a58b0cf`,
produces vendor-tree SHA-256
`e7304e86be5ac39fc9ac4ecafcac9e1153e9d342ed666ced89516c35e0bea22c`
using the tree-hash algorithm below. Only three files differ:

- `Cargo.toml`: replace optional P-384 0.13 with exact 0.14.0.
- `src/certs/snp/ecdsa/mod.rs`: preserve the reversed first 48 scalar bytes
  using fixed arrays accepted by the new API; discard the same unused padding.
- `src/firmware/guest/types/snp.rs`: finalize the existing SHA-384 0.10 digest
  of the same report prefix `[..0x2a0]` and pass those bytes to the new
  `PrehashVerifier` in both existing verifier implementations. This avoids
  crossing digest trait versions or hashing the digest a second time.

No RSA certificate/CRL algorithm, trust anchor, report framing, public authority,
device access or cryptographic arithmetic implementation is locally rewritten.
The Apache-2.0 `LICENSE` remains unchanged, SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
`scripts/check-sev-p384-scope.py` independently reconstructs every vendor file
and rejects any additional edit. The existing public-RSA exception remains
restricted to its original pinned source/callers and advisory; its guard also
authenticates this SEV reconstruction before allowing that existing exception.

### ctutils 0.4.5 and proof boundary

The current `ctutils 0.4.5` is unmodified upstream, including its const API.
Archive `sources/ctutils-0.4.5.crate` has SHA-256
`38d28fb6aa7dd680b3ffd1a3e64e115c177bdba63c0ae7f9cd48129ff05c4fa0`,
VCS `88d6e90d4cfd2fc3333d00e13c99241507d2138f`. Vendor-tree SHA-256 is
`063c02ff15389aa5695cca949ac0032382abc36fa6beb2f504fe3dd6b5571f41`.
All mask `to_u8`/`black_box` and 32-bit u128-half barriers from 0.4.4 remain.
The upstream 0.4.5 changes add integer primitives and Thumb-1 barriers, so the
new linked crypto-bigint/P-384 route and subtraction/zero-count/carry primitives
require fresh tests and codegen review on the selected compiler and targets.
The old seventeen entrypoint results alone do not establish this new scope.
The exact 0.4.4 source, compatibility patch, fixtures and evidence are retained;
the current graphs must select only 0.4.5. All other validated backports remain.

Primary references: [new RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
[SEV original source](https://github.com/virtee/sev/tree/a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5),
[P-384 release metadata](https://crates.io/api/v1/crates/p384/0.14.0),
[crypto-bigint release metadata](https://crates.io/api/v1/crates/crypto-bigint/0.7.9),
[ctutils release metadata](https://crates.io/api/v1/crates/ctutils/0.4.5).

## Historical backport baseline

VOLPAROSSA targets Debian 13 amd64 and its stable Rust 1.85 compiler. The
upstream fixed releases `hickory-proto 0.26.1`, `hickory-resolver 0.26.2`
and `time 0.3.47` all
declare Rust 1.88, so the locked compatible releases are reconstructed from
their exact crates.io archives and receive minimal source backports. The
published `libp2p-yamux 0.47.0` also retains a `yamux 0.12` compatibility
backend selected whenever a configuration setter is used, including the
non-deprecated `set_max_num_streams`. VOLPAROSSA's current call sites used the
newer default, but both backends remained in the resolved graph. The
Rust-1.85-compatible reconstruction backports the upstream
single-backend design and pins fixed `yamux 0.13.10`. Package names and
semantic versions are intentionally unchanged.

These are third-party sources and retain their upstream license terms. Hickory
and time remain Apache-2.0 OR MIT with license files copied byte-for-byte from
their crates.io archives. `libp2p-yamux` remains MIT; because its archive omits
the license file, the exact repository-root license from its recorded VCS
revision is retained alongside the reconstructed source.

## Locked inputs

| Crate | crates.io archive SHA-256 | crates.io VCS revision | Original MSRV |
|---|---|---|---|
| `hickory-proto 0.25.2` | `f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502` | `527c9f470a418cf6b92da902ea0aaa5749963d59` | 1.71.1 |
| `hickory-resolver 0.25.2` | `dc62a9a99b0bfb44d2ab95a7208ac952d31060efc16241c87eaf36406fecf87a` | `527c9f470a418cf6b92da902ea0aaa5749963d59` | 1.71.1 |
| `time 0.3.41` | `8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40` | `cc35dcfcde917bb833c114e2b4c00292a374c4ba` | 1.67.1 |
| `libp2p-yamux 0.47.0` | `f15df094914eb4af272acf9adaa9e287baa269943f32ea348ba29cfb9bfc60d8` | `9736aacf814eb7b9df0372c5f9adcffba8a4b212` | 1.83.0 |

The source archives are retained under `sources/`. Their SHA-256 values are
the checksums recorded by crates.io and the pre-patch `Cargo.lock`.

## Reviewed patches

| Patch | SHA-256 | Resulting vendor-tree SHA-256 |
|---|---|---|
| `patches/hickory-proto-0.25.2-rustsec.patch` | `bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a` | `65d70d1559f2209a76b3ca68357c86bd94c9046e0b5dd22b0b3458ad418b1786` |
| `patches/hickory-resolver-0.25.2-dnssec.patch` | `2e070665e78337e620dfb3f8c15ff09a938ad3fa711e240798732de4c204f1b2` | `cce65437d685b2911c283c4f739fbe08017ae1cd4b80a5895cba3f99110c9b3e` |
| `patches/time-0.3.41-rustsec.patch` | `bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a` | `722fc9e265043f6d683a365596063ad3b192a7d4dce542f9aa56bee65ccfdd7b` |
| `patches/libp2p-yamux-0.47.0-single-backend.patch` | `1a845f6cfaa57c993b54f654dc8e9294a450de8c46be323618481a7cc750740d` | `a7a9977042b6d9f602e98d67dc8409c485b5e588f79f8567b9b5b6ec9587e4fb` |

The tree hash algorithm is:

```sh
find . -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum |
    sha256sum
```

The Hickory proto patch:

- caps the linear `BinEncoder` name-compression candidate set at the upstream
  limit of 64 and tests that a 65th candidate is not retained, remediating
  RUSTSEC-2026-0119;
- rejects an NSEC3 proof before allocation when the SOA is not an ancestor of
  the query name and tests the cross-zone case, remediating
  RUSTSEC-2026-0118.

### Resolver validation and CNAME scope

[GHSA-5j98-2g5x-46v6](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-5j98-2g5x-46v6)
describes a lookup API returning success for DNSSEC-bogus records when validation
is enabled. The resolver backport applies the answer-record check from upstream
commit `92f93c0b889f6a292bc943304d88c4c6561fe1b9` before cache insertion and CNAME
handling. It uses the existing 0.25 error type; the 0.26 network/error/server
reorganization is not imported. Negative proof errors already remain errors in
the pinned 0.25 path. Focused regressions cover the error boundary, cache behavior
and preservation of non-bogus and validation-disabled behavior.

The production shared-DNS validator uses `DnssecDnsHandle` and separately requires
`Proof::Secure` for every accepted A/AAAA record. It does not use the affected
resolver convenience API. Discovery uses the resolver through `libp2p-dns` with
its existing system configuration; this change does not turn that path into a
DNSSEC-authenticated service or alter host DNS settings.

[GHSA-6f2x-v7q7-m7m5](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-6f2x-v7q7-m7m5)
describes unnecessary recursive queries for unrelated CNAME records. Its upstream
fixes `4689fc8d3ddd3e3f99ec1b7be4e2e9e78afd2e6b` and
`ccd6952378f250c714fc2af0cb1053e1c179f832` change the 0.26 recursor. In 0.25 that
implementation belongs to the separate `hickory-recursor` crate, absent from both
VOLPAROSSA graphs. The pinned stub instead follows matching answer-section names
through one next-query chain. Its unrelated-answer, authority/additional and
bounded-chain cases are covered by regressions; graph checks reject introduction
of the recursor. This is a limited source-and-reachability assessment, not a claim
that every 0.25 Hickory deployment is unaffected. No advisory dismissal or new
scanner exception is introduced for either GHSA.

As with the Yamux reconstruction, the resolver crate's embedded development
`Cargo.lock` is omitted from the vendor tree. The unchanged archive preserves it;
the root, fuzz and isolated regression locks define the graphs actually built.

### Existing time and Yamux backports

The `time` patch ports the upstream 32-level RFC 2822 comment recursion bound
and tests both the accepted boundary and fail-closed over-limit case,
remediating RUSTSEC-2026-0009.

The `libp2p-yamux` patch backports the single-backend structure from upstream
rust-libp2p change `efc2bfc156b592838c7d469dab345714069619d6`. It removes the
deprecated `yamux 0.12` branch and `either` dispatch, pins `yamux 0.13.10`, and
retains the non-deprecated `set_max_num_streams` API. The backport deliberately
keeps `libp2p-yamux 0.47.0`'s `read_after_close(false)` default; copying the
future 0.48 implementation verbatim would silently change that behaviour.
The crate archive's non-authoritative development `Cargo.lock` is omitted from
the reconstructed library tree so dependency scanners cannot mistake its
retired test graph for product code. The exact source archive remains retained.
Because the published crate omitted a license file, the unchanged repository
root MIT license from the recorded VCS revision is added with SHA-256
`e10098b8c52fd18ad0f116aac2c0dba1e99ca125d6848640c00688e160a3ee7d`.

GitHub advisory GHSA-vxx9-2994-q338 / CVE-2026-32314 classifies Yamux versions
below 0.13.10 as affected by an oversized first-stream `Data|SYN` panic. The
root and fuzz graphs now contain only fixed `yamux 0.13.10`, so this change
requires no advisory ignore or scanner exemption.

The `yamux 0.13.10` crates.io archive declares Apache-2.0 OR MIT but contains
no top-level license files. Its embedded VCS metadata records revision
`38e9944f8fbb723a3a4df575cfb15109efcb2d24`; that object was not independently
resolvable during review. The official lightweight `yamux-v0.13.10` release
tag resolves to `70db05dc63e8368bd0559a5ec0dba6e5fc2bdd41`. Its exact
`LICENSE-APACHE` and `LICENSE-MIT` files are retained under
`licenses/yamux-0.13.10/` with SHA-256 values
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
and `ec353d4fecf7963b4c054384557e5dbc3c7a717997eb4a3815b315721a6aa75a`.
The package collector uses these files only for the exact crate name, version,
license expression, crates.io source, and embedded VCS identity.

The Hickory diff also declares the non-default
`volparossa-backport-regressions` feature. It exposes only a doc-hidden boolean
adapter to the same private `verify_nsec3` call so the isolated GPL-3.0-only
test harness can execute the cross-zone path with `dnssec-ring`. The production
feature-graph gate rejects this feature and the unused aws-lc DNSSEC backend; the adapter
does not change Hickory's default features or semantic package version.

The bounded positive A/AAAA DNS-sharing resolver now explicitly enables
`dnssec-ring` in `volparossa-udp`. The previous product guard excluded DNSSEC
because no production caller needed it, not instead of applying the NSEC3 fix.
The exact reviewed cross-zone fix and offline regression remain mandatory.
The new wrapper accepts only bounded positive A/AAAA and DNSKEY/DS/RRSIG
chains, requires `Proof::Secure`, rejects aliases/wildcards/negative proof
shapes, and keeps the existing compiled root anchors. It preserves original
received RR/RRSIG TTL bounds separately from Hickory's adjusted TTL. No vendor
bytes, trust-anchor files, licenses, or cryptographic implementation change.
The standalone fuzz graph does not depend on the UDP resolver and still
forbids both DNSSEC backends and the regression adapter.

The isolated harness has its own Rust-1.85-targeted `Cargo.lock` with SHA-256
`965c606acf0c93d9a9d6b8415b3ae503185e8b3ec7eecf3d6251c9047cd14659`.
It tests compression, NSEC3, RFC 2822 parsing, resolver validation and CNAME
scope, plus two bounded Yamux cases, without network access:

```sh
cargo test \
    --manifest-path third_party/rust/backport-regressions/Cargo.toml \
    --locked \
    --offline
```

The fixed Hickory compression and `time` recursion logic was compared against
the official crates.io 0.26.1 and 0.3.47 sources respectively. Hickory's
0.26-line NSEC3 validator moved to `hickory-net`; the 0.25 backport applies
the same documented cross-zone precondition directly at the old
`verify_nsec3` boundary.

The Yamux regression sends a `Data|SYN` frame for a new stream with a body of
`DEFAULT_CREDIT + 1`. The pinned implementation must terminate processing
promptly and fail closed without unwinding or admitting a stream. Root and fuzz
metadata checks additionally require exactly one path `libp2p-yamux 0.47.0`,
exactly one registry `yamux 0.13.10`, and no `yamux 0.12` package. A separate
public-wrapper regression exercises `set_max_num_streams`, buffers an inbound
stream, drops its owning connection, and proves the preserved
`read_after_close(false)` default returns immediate EOF without exposing the
buffered bytes.

## Advisory scanner treatment

RustSec scanners identify packages by semantic version and therefore still
match the patched 0.25.2 and 0.3.41 sources. The three IDs are exempted only
after `scripts/check-rust-dependencies.sh`:

1. verifies the exact archive and patch SHA-256 values;
2. reconstructs each vendor tree in a fresh temporary directory;
3. byte-compares the reconstruction with the Cargo path override;
4. verifies unchanged upstream license files and the complete tree hashes;
5. verifies the exact isolated-harness files and lock, then executes the
   compression, NSEC3, RFC 2822, resolver and Yamux regressions offline;
6. proves both locked graphs use the reviewed local paths and contain only fixed
   `yamux 0.13.10`; production explicitly enables only Hickory `dnssec-ring`,
   while the standalone fuzz graph excludes DNSSEC; both reject the
   regression-only feature and `dnssec-aws-lc-rs`;
7. runs CVSS 4.0-capable cargo-deny advisory, license, ban, and source checks; and
8. independently runs a CVSS 4.0-capable cargo-audit without fetching.

These are locally remediated advisory-version matches, not accepted
vulnerabilities. Any byte change to an archive, reviewed patch, license, or
vendor tree fails before the exemptions reach cargo-audit.

The gate requires `cargo-deny >= 0.18.6` and `cargo-audit >= 0.22.1`. Set
`CARGO_AUDIT` to a specific
executable when it is not on `PATH`, and set `RUSTSEC_ADVISORY_DB` when the
local advisory checkout is not in a standard Cargo cache location. The gate
prints the exact advisory database commit and always passes `--no-fetch`.

## Removal condition

Remove each path override, archive, patch, and scanner exemption together once
the Debian 13 compiler can build a fully fixed compatible upstream release.
For `libp2p-yamux`, that means a published single-backend release compatible
with the project toolchain and with the preserved read-after-close policy.
Never carry these patches into a newer package without re-auditing whether the
upstream code already contains the fix.

## ctutils 0.4.4: fixed upstream source adapted for Rust 1.85

The root and fuzz graphs use exactly one local `ctutils 0.4.4`. Its original
crates.io archive SHA-256 is
`12218662ccac37d9714f2191252553d67585b97df8c839cbe49e0bde278dc865`,
with embedded RustCrypto/utils commit
`a993c0ba50db6510d8db15a6219572de65115438` (release PR1569).
The fixed upstream baseline includes the mask optimization barrier from PR1567
`a43d7f37a93b2db3b1bebccc6f5fa8ea6ef76910` and 32-bit u128 comparison fix
from PR1568 `d21441f19e4654e006be73d9234dd05d2a49c706`, addressing
[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html).
This is VOLPAROSSA's modified 0.4.4 source, with no advisory exemption.

| Reviewed input | SHA-256 |
|---|---|
| `patches/ctutils-0.4.4-rust1.85.patch` | `1e6bf3aac8e37c897e88a59fe5f60aaa6c3d7090f6c2a2d629015a20d5967ac6` |
| Complete `vendor/ctutils-0.4.4` tree, using the algorithm above | `4c18cd159e5013b4ed127137ca157dc8fb6fd2f3239ab9b90602765d41273635` |
| Adapted normalized manifest | `147a8c6bd85279767624f7b484677d700f52c99ef9a2581efeca2ffe24d81f4b` |

The original Apache-2.0 and MIT license files, upstream runtime algorithms,
feature definitions, data layout, `black_box(self.0)`, mask calls to `to_u8()`,
three barriers in the u128-halves algorithm, and CtLt/CtGt routing remain exact.
Only the manifest MSRV, bit-preserving same-width casts, and necessary const
qualifications/test bindings change. `scripts/check-ctutils-scope.py` derives
this closed permitted surface directly from the original archive; its mutation
tests reject changes to the barriers, masks, routing, assertions and licenses.
The general dependency verifier also reconstructs and hashes the entire tree,
and checks exact root/fuzz path-package identity before scanning.

There is an explicit compile-time API limitation: these **20 public methods are
ordinary functions in this variant**, retaining their runtime signatures:

- `Choice`: `to_bool`, `to_u8`, `to_bool_vartime`, `to_u8_vartime`;
  `to_u8_mask`, `to_u16_mask`, `to_u32_mask`, `to_u64_mask`, `to_u128_mask`;
  `select_i64`, `select_u8`, `select_u16`, `select_u32`, `select_u64`, `select_u128`;
  `from_u128_lt`, `from_u128_le`.
- `CtOption`: `expect_ref`, `expect_copied`, `into_option_copied`.

The private halves helper and corresponding upstream test bindings also become
runtime functions/bindings. All other const qualifications remain unchanged.
Original upstream rustdoc descriptions are preserved; their const claims for
these methods do not apply to this local variant. Rust's `black_box` is available
at runtime in 1.85, but its const support requires 1.86. Replacing the newer
same-width cast methods and reducing constness preserves that runtime barrier;
merely lowering upstream's manifest MSRV would not suffice. This is not a claim
of full compile-time API compatibility or of universal constant-time execution.

### Bounded hosted verification and remaining acceptance

The existing Quality workflow has an explicit `ctutils_compatibility=true`
manual mode, bound to `core_revision` equal to the workflow's exact source SHA.
Normal PRs retain the ordinary Quality gate. The opt-in uses
`scripts/run-ctutils-hosted.py`, which refuses development-host/self-hosted
execution before installation or compilation. It performs:

- Original upstream unit/property tests (1024 property cases), with no features,
  alloc, subtle, and alloc+subtle, for adapted Rust **1.85.0** and unmodified
  original Rust **1.87.0**, on amd64 and actual `i686-unknown-linux-musl`.
  The bundled pinned `rust-lld` supplies 32-bit linking without a host multilib
  installation. Unsupported 32-bit execution is a failure, not a skipped pass.
- `ctutils-regressions` value tests and actual digest/HMAC-output and
  Poly1305/universal-hash verification, plus real Core route-credential and
  private-message HPKE tests on 1.85/amd64. These tests exercise real consumers;
  the codegen wrapper is not a substitute for Core's HPKE tests.
- Linked release codegen and LLVM capture, named secret-input entrypoints,
  disassembly and artifact hashes for both compilers/targets. The profile matches
  Core's opt-level 3, one codegen unit, thin LTO, panic abort and debuginfo stripping.

The receipt keeps functional execution separate from **required independent
codegen/dataflow review**. Compare the masks, selects, u128 lt/le and trait
routing, and linked digest/universal-hash consumer paths on the actual 1.85
compiler; branch counts or value tests alone do not prove constant-time behavior.
The original 1.87 reference is comparative evidence, not proof transferred to
1.85. No BINSEC execution or formal cryptographic proof is claimed by this recipe.
Hosted execution and codegen review remain pending when this source is introduced.
Full ordinary Quality/offline audits are a separate required check; the newly
reported unmaintained zvariant-family advisories are open findings, with no new
ignore, MSRV-major port or scope reduction in this change.
