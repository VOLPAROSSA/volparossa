# Historical Weather archive input contract (F09)

This candidate is stacked on preservation PR345, commit
`e06ed7c2987cfc7650bd4cce1d8e9ec9aeb02392`. It prepares the four existing Weather
consumers for an explicitly admitted immutable release. **The checked-in archive
admission is blocked. This candidate must remain a draft until publication rights,
the actual release and hosted input retrieval have been verified.**

The user authorized a historical archive under
`evidence/weather-inputs-2026-10-23` in `VOLPAROSSA/volparossa`, targeting original
Core admission commit `89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1`. That authorization
requires a complete privacy and redistribution review before publication. No
release, tag or asset has been created for this candidate.

## Publication gate

The seven original ZIPs remain privately preserved and match their original
checksums. The proposed public set consists of those ZIPs, four byte-identical
public admission snapshots and the minimal preservation manifest: twelve assets,
319,181,806 bytes in total. The manifest is 15,987 bytes with SHA-256
`0201e6187e1aa0e0d50dbd1537449cd8b39c59615c97d3cb1eeef4c84b1a6795`.

Redistribution review is incomplete. In particular, the Drizz.li and Overmorrow
asset ZIPs include branded Firefox with added VOLPAROSSA configuration. The
[Mozilla distribution policy](https://www.mozilla.org/en-US/foundation/trademarks/distribution-policy/)
distinguishes unaltered distribution from modified branded versions. Coverage of
this particular redistribution by applicable permission has not been established.
This is a publication blocker, not a finding that source-code licenses prohibit
private preservation or that infringement has been legally determined.

The content review also found missing required notice text for the Svelte runtime
in the Drizz.li build and the Noto font in the Overmorrow build. Exact source
availability and a release-body source pointer do not by themselves supply the
missing license copies or establish trademark permission. Resolve the complete
notice and permission set before deciding a final public payload.

Do not publish the seven-artifact set, invent release identifiers or enable the
archive route while a rights, notice, source-availability or privacy blocker
remains. Renaming a release or describing it as evidence does not establish
distribution permission. Keep the original ZIP bytes and historical records.

## Explicit archive admission

`tests/helper/weather-release-archive-v1.json` has two strict states:

- `blocked`: known asset names, sizes, digests and original provenance remain
  pinned; unknown repository/release/asset IDs and the tag object are null.
  Offline validation reports that the structure is valid but ineligible. Fetch
  fails before network access or output creation.
- `admitted`: all actual identifiers must come from authenticated publication
  readback. The reason for blocking is null, and every expected identity is
  present. There is no command-line override for state, host, URL or admission.

The four historical admissions remain byte-identical. The new archive admission
binds their snapshots and all seven original ZIP digests to one published,
immutable prerelease and its exact tag object. It does not reinterpret the
original Actions expiry or make a historical API response a current observation.

The fixed consumer keys are `decoder-abi`, `drizzli-v4`, `overmorrow-v5` and
`android-v6`. Each can request only its existing decoder/ABI/assets/proof roles.
The downloader verifies the complete twelve-asset metadata set, the manifest and
four snapshots before selected ZIP download and safe extraction. Downloaded bytes
must match the expected lengths and SHA-256 values. Extracted files remain
nonexecutable. Existing ABI and bundle validators remain the next independent
input gate.

The archive route never queries historical Actions endpoints, chooses a latest
release, follows an unverified mirror or falls back on failed admission. A failed
download or metadata check remains a failure. Successful input retrieval is
historical-input evidence; it does not establish current origin acquisition,
joined delivery, mobile operation or product acceptance.

## Verification and eventual activation

The four workflows expose a default-false `archive_inputs_only` dispatch input.
The input-only path verifies source and archive inputs before VM/SDK/toolchain
installation, large image downloads or runtime execution. The full path retains
its existing resource, source, execution and cleanup requirements. A blocked
archive is rejected in either path.

Before activation:

1. Resolve every publication-review blocker and record the exact lawful payload.
2. Reconfirm repository immutability. Create a draft prerelease on the approved
   original Core commit, upload only the reviewed assets, read them back and
   verify their bytes before publishing. Keep it out of Latest.
3. Independently recheck the published release, immutable flag, tag-to-commit
   binding, all asset IDs, sizes, API digests and actual download hashes.
4. Populate actual IDs and change the admission to `admitted` in a reviewed
   activation commit. Preserve all original admission hashes and source pins.
5. Obtain independent technical review, run targeted parser/extraction/wiring
   checks, then run each actual workflow once with `archive_inputs_only: true`
   on the same exact candidate revision. Preserve original run and report IDs.
6. Merge only through the normal manual review process. Verify which source is
   operational after integration before closing F09.

Parser/protocol fixtures prove implementation behavior. They cannot establish
that an unpublished release exists or that hosted consumers can retrieve it.
The focused `Weather archive source contracts` workflow checks these fixtures and
existing bundle/wiring boundaries on the stacked PR without running acceptance
trials. It uses the existing hosted Python and a read-only checkout.
Until the above checks succeed, F09 remains open for hosted continuity after the
original artifacts expire on 26 October 2026.
