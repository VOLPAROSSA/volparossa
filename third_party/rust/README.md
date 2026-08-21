# Reviewed Rust security backports

VOLPAROSSA targets Debian 13 amd64 and its stable Rust 1.85 compiler. The
upstream fixed releases `hickory-proto 0.26.1` and `time 0.3.47` both
declare Rust 1.88, so the locked compatible releases are reconstructed from
their exact crates.io archives and receive minimal source backports. Package
names and semantic versions are intentionally unchanged.

These are third-party sources. They remain under their upstream
Apache-2.0/MIT dual-license terms; the license files in each vendor directory
are byte-for-byte copies from the corresponding crates.io archive.

## Locked inputs

| Crate | crates.io archive SHA-256 | crates.io VCS revision | Original MSRV |
|---|---|---|---|
| `hickory-proto 0.25.2` | `f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502` | `527c9f470a418cf6b92da902ea0aaa5749963d59` | 1.71.1 |
| `time 0.3.41` | `8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40` | `cc35dcfcde917bb833c114e2b4c00292a374c4ba` | 1.67.1 |

The source archives are retained under `sources/`. Their SHA-256 values are
the checksums recorded by crates.io and the pre-patch `Cargo.lock`.

## Reviewed patches

| Patch | SHA-256 | Resulting vendor-tree SHA-256 |
|---|---|---|
| `patches/hickory-proto-0.25.2-rustsec.patch` | `bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a` | `65d70d1559f2209a76b3ca68357c86bd94c9046e0b5dd22b0b3458ad418b1786` |
| `patches/time-0.3.41-rustsec.patch` | `bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a` | `722fc9e265043f6d683a365596063ad3b192a7d4dce542f9aa56bee65ccfdd7b` |

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

The Hickory diff also declares the non-default
`volparossa-backport-regressions` feature. It exposes only a doc-hidden boolean
adapter to the same private `verify_nsec3` call so the isolated GPL-3.0-only
test harness can execute the cross-zone path with `dnssec-ring`. The production
feature-graph gate rejects this feature and both DNSSEC backends; the adapter
does not change Hickory's default features or semantic package version.

The isolated harness has its own rustc-1.85-resolved `Cargo.lock` with SHA-256
`c56a2c8a797466a7c38171bd7e806d8b8bfc0d9dd2cfdc1d3f5a0984262024eb`.
It executes all three backport regressions without network access:

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

## Advisory scanner treatment

RustSec scanners identify packages by semantic version and therefore still
match the patched 0.25.2 and 0.3.41 sources. The three IDs are exempted only
after `scripts/check-rust-dependencies.sh`:

1. verifies the exact archive and patch SHA-256 values;
2. reconstructs each vendor tree in a fresh temporary directory;
3. byte-compares the reconstruction with the Cargo path override;
4. verifies unchanged upstream license files and the complete tree hashes;
5. verifies the exact isolated-harness files and lock, then executes the
   compression, NSEC3, and RFC 2822 regressions offline;
6. proves the locked feature graph uses both local paths and does not enable
   Hickory `dnssec-ring`, `dnssec-aws-lc-rs`, or the regression-only feature;
7. runs cargo-deny license, ban, and source checks; and
8. runs a CVSS 4.0-capable cargo-audit without fetching.

These are locally remediated advisory-version matches, not accepted
vulnerabilities. Any byte change to an archive, reviewed patch, license, or
vendor tree fails before the exemptions reach cargo-audit.

The gate requires `cargo-audit >= 0.22.1`. Set `CARGO_AUDIT` to a specific
executable when it is not on `PATH`, and set `RUSTSEC_ADVISORY_DB` when the
local advisory checkout is not in a standard Cargo cache location. The gate
prints the exact advisory database commit and always passes `--no-fetch`.

## Removal condition

Remove each path override, archive, patch, and scanner exemption together once
the Debian 13 compiler can build a fully fixed compatible upstream release.
Never carry these patches into a newer package without re-auditing whether the
upstream code already contains the fix.
