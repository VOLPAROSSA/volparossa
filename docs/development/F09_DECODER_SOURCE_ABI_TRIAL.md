# Fixed source-v1 decoder ABI trial

The `source-v1` mode of the existing Weather decoder workflow now uses a separate
final decoder-input admission after independently reviewed native ABI run
40060819389 (attempt 1, job 120773716703) on Core
`382df4d5b4e6d7434828dec00bee6d7d620ed805`. The manual default and the ordinary
consumer path with absent workflow inputs both select `source-v1`. Every step
uses the effective `DECODER_MODE`; `historical-v1` remains an explicit historical
mode with its original controls and admission bytes.

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

The separate `tests/helper/weather-decoder-source-v1.json` admission has ID
`weather-decoder-source-20261024-v1` and raw SHA-256
`b38262cbe95cef4aa31e54b677cd05ba9d95a5b90cefbb0e41f250c41b87a8e2`.
It binds the unchanged trial, all 14 payload files, source/environment pins, both
cold builds and the actual successful ABI run. Both metadata artifact digests,
the original trial/ABI reports and both original VM cleanup receipts are fixed
provenance. Artifact IDs never become download dependencies: each source-v1 run
rebuilds from the fixed primary sources and compares the admitted bytes. Technical
review digest `226fa7ca2de091c7ec8f90afd114c4663f38d2593373fd7c4a566cb8dfc79baf`
is evidence provenance, not a digital signature.

The caller cannot select another admission path/hash. `source-admission-info`
checks the pinned raw record, closed schema, exact trial/source/payload bindings
and actual environment-lock bytes before runner preparation. The guest entry and
shared source ABI executor repeat this admission check before installation or
execution. New reports include the admission ID and digest; their existing
`admitted=false` flag means the report itself does not create another admission.
The immutable trial and original successful reports retain their original false
admission flags. No current-commit self-pin is used.

The reviewed native result proves the exact decoder's relocated offline ABI,
ecCodes 2.44.0 and nonconstant CCSDS values 0 and 495 in the fixed Debian 13 AMD64
environment, with complete payload/environment checks and successful two-VM
cleanup. This admits only disposable decoder-test inputs. It does not authorize
production, prove weather-origin acquisition, Core delivery, browser/Android
acceptance, full ecCodes upstream/sanitizer coverage, or default-branch integration.
The other three consumers and F09 as a whole remain open.

Local tests are inert source/data/shell fixtures, not new ABI evidence. This
admission/consumer change requires independent source review and one targeted
hosted source-v1 consumer run on its exact commit. No native trial is executed on
the development host.
