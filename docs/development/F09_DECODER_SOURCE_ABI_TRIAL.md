# Fixed source-v1 decoder ABI trial

The separate `source-v1` mode of the existing Weather decoder workflow is a
reviewable implementation candidate. It has no completed ABI result yet. The
historical default and all historical admissions remain unchanged.

The immutable `tests/helper/weather-decoder-source-trial-v1.json` record authorizes
only disposable trial inputs. It binds producer Core `b027d87367262c62d1e70c61102ba87513bbfeec`,
Weather `05a7350c702625d99d610a882f50b2fd639edc4e`, the original three source archives,
the exact signed Debian package environment, and all 14 reviewed payload files
(93,841,627 bytes). Independent review of cold builds 40057456323 and 40057858381
approved these inputs. Their complete payload-manifest digest is
`b95fa04b4e9c4024d0bc35442321f39c73c2344c3864c686537fba78cd9d8d35`;
the deterministic buildmanifest digest is
`222bfa693f5dbd4350e311a41e92732c40ffe3aefd8a83678ecd2334fb7292f7`.
The public trial record contains only bounded source/evidence metadata, not the
private review or binary payload. It does not contain its evaluator's own commit.

A source-v1 workflow invocation uses the existing VM runner twice in sequence:

1. A fresh pinned Debian 13 guest rebuilds the fixed Weather recipe using the
   existing source-build mode. The existing bounded per-member readback transfers
   the private payload to the same runner. The raw payload manifest and all 14
   files must match the fixed trial record before the ABI guest starts.
2. A second fresh pinned guest receives four verified Weather source files and
   the fixed 14-file payload at separate private paths. It prepares the same exact
   signed package environment with `source_inventory(build_mode=True)`. It does
   no compilation. Exact package/base maps authenticate readelf, Python, bwrap,
   prlimit, the loader, and the checked development/runtime libraries.
3. The original relocated, offline/read-only ABI executor uses an explicit
   source-v1 input adapter. It checks ELF diagnostics, version and both
   nonconstant CCSDS probe points. It rechecks every payload member, including
   unused binaries, libaec, original notices and the unchanged buildmanifest.
   The locked environment is checked before and after execution.

The combined job ceiling is 80 minutes, retaining the existing separate build
and ABI command/VM bounds and cleanup. Missing or changed records/locks, wrong
profiles, extra or modified files, unsafe modes/links, failed commands and
uncertain cleanup fail closed. Source-v1 never retrieves historical artifacts
or accepts caller-selected record paths/expected hashes. The runner-local binary
payload is deleted after use; uploads select only bounded closed text metadata
and logs for each guest. Both guest cleanup receipts must be reviewed with the
actual step results.

Local tests are inert source/data/shell fixtures, not ABI evidence. After source
review, one explicit hosted source-v1 invocation is needed. A successful result
still requires independent evidence review before any separate final
`weather-decoder-source-v1.json` admission. No final admission is created by this
implementation. Full ecCodes upstream/sanitizer coverage, four consumer proofs,
product acceptance and default-branch integration remain separate requirements.
