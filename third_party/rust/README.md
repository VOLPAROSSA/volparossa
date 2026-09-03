# Reviewed Rust dependency security changes

VOLPAROSSA targets Debian 13 amd64 and its stable Rust 1.85 compiler. The
upstream fixed releases `hickory-proto 0.26.1` and `time 0.3.47` both
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
| `time 0.3.41` | `8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40` | `cc35dcfcde917bb833c114e2b4c00292a374c4ba` | 1.67.1 |
| `libp2p-yamux 0.47.0` | `f15df094914eb4af272acf9adaa9e287baa269943f32ea348ba29cfb9bfc60d8` | `9736aacf814eb7b9df0372c5f9adcffba8a4b212` | 1.83.0 |

The source archives are retained under `sources/`. Their SHA-256 values are
the checksums recorded by crates.io and the pre-patch `Cargo.lock`.

## Reviewed patches

| Patch | SHA-256 | Resulting vendor-tree SHA-256 |
|---|---|---|
| `patches/hickory-proto-0.25.2-rustsec.patch` | `bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a` | `65d70d1559f2209a76b3ca68357c86bd94c9046e0b5dd22b0b3458ad418b1786` |
| `patches/time-0.3.41-rustsec.patch` | `bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a` | `722fc9e265043f6d683a365596063ad3b192a7d4dce542f9aa56bee65ccfdd7b` |
| `patches/libp2p-yamux-0.47.0-single-backend.patch` | `1a845f6cfaa57c993b54f654dc8e9294a450de8c46be323618481a7cc750740d` | `a7a9977042b6d9f602e98d67dc8409c485b5e588f79f8567b9b5b6ec9587e4fb` |

The tree hash algorithm is:

```sh
find . -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum |
    sha256sum
```

The Hickory patch:

- caps the linear `BinEncoder` name-compression candidate set at the upstream
  limit of 64 and tests that a 65th candidate is not retained, remediating
  RUSTSEC-2026-0119;
- rejects an NSEC3 proof before allocation when the SOA is not an ancestor of
  the query name and tests the cross-zone case, remediating
  RUSTSEC-2026-0118.

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
feature-graph gate rejects this feature and both DNSSEC backends; the adapter
does not change Hickory's default features or semantic package version.

The isolated harness has its own rustc-1.85-resolved `Cargo.lock` with SHA-256
`08e7bcd46d2e3f7411e8f4e855c70027f627be6061f63ab459c43f41a687c5cc`.
It executes all three backport regressions plus two bounded Yamux regressions
without network access:

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
   compression, NSEC3, RFC 2822, and Yamux regressions offline;
6. proves both locked graphs use all three local paths, contain only fixed
   `yamux 0.13.10`, and do not enable Hickory `dnssec-ring`,
   `dnssec-aws-lc-rs`, or the regression-only feature;
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
