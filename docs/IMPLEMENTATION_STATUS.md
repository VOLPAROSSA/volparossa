# VOLPAROSSA implementation status

This is the current execution index for the complete [DICN goal](development/GOAL.md),
including [DPS](development/GOAL.md#dps) and
[Studio/hosting](development/GOAL.md#studio). Use [AGENTS.md](../AGENTS.md)
for engineering boundaries and the [development workflow](development/CODEX_WORKFLOW.md)
for scoped execution. A milestone does not reduce the agreed goal.

Reorganized: 2026-10-26; evidence reconciled: 2026-10-27. Technical evidence
combines the recorded 2026-10-23 checkpoint at `89d3aea585ed` with the
[PR343 evidence supplement](archive/integration-evidence-pr343-20261023.patch.txt)
at `a52ab4e77184`. That supplement preserves the original source/tree bindings,
artifact IDs, digests and failures without restoring obsolete workflow instructions.
The four formerly pending runs identified below have refreshed GitHub run/job
metadata as of 2026-10-27; their artifacts were not revalidated in this edit.
That documentation reconciliation ran no new product trial. Refresh relevant branch/check ownership before
resuming; an old source result does not establish current composition acceptance.

[Current work](#current-integration-and-active-work) ·
[Priorities](#execution-priorities-and-next-milestones) ·
[Retained work](#retained-branches-and-resumption-dependencies) ·
[Historical evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md) ·
[Completion](#definition-of-done)

The [historical ledger](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md) preserves the previous
1,424,479 bytes unchanged, including original source revisions, run/artifact IDs,
digests, failures and scorecard. Its dated model assignments, session status and
procedural instructions are historical; current AGENTS/workflow supersede them.
The [local source archive](archive/requirements-20261023/README.md) retains the
original bytes for offline inspection. Read only evidence relevant to the task.

## Current integration and active work

### Development branches — 18 November 2026

The central build follows the [owner’s development mandate](development/GOAL.md#autonoom-onderhoud-en-updates).
Each trial below identifies the revision it exercised. The default branches now
include the [Studio editor export](https://github.com/VOLPAROSSA/volparossa/pull/342),
the [Weather decoder rebuild](https://github.com/VOLPAROSSA/volparossa/pull/350),
the [Image owner recovery key](https://github.com/VOLPAROSSA/volparossa-image/pull/21)
and the [Bank TEST transfer example](https://github.com/VOLPAROSSA/volparossa-bank/pull/13).

- The [integrated Core quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44372813034)
  passed its Storage contracts, build, integration and unprivileged quality
  jobs on `dc5a1bac`. Cargo reported 4,476 passed and 21 ignored in the
  workspace test step. The topology and application trials below identify
  the source revisions they each exercised.
  The [subsequent combined Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44401197512)
  passed all three jobs on `6350130d`, which integrates the Storage bind
  diagnostic, exact release selection and restored-site deployment fixture.
  Its workspace test step reported 4,493 passed, zero failed and 21 ignored.
  On `ed1764f6` the MPTCP client rechecks the signed route deadline after
  waiting for the previous flow's retirement. When the route expired during
  that wait, the adapter sent zero new helper acquisition requests. A still
  valid route issued its normal request. Both IPC regressions passed, as did
  strict Clippy and the workspace suite (4,495 passed, zero failed, 21 ignored).
  These tests isolate the admission window. The cross-application reservations
  have separate evidence in the Storage section.
  [Route lifetime quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44409970591)
  On the combined `94a0f06d` development revision, all three Quality jobs
  passed. The workspace step reported 4,495 passed, zero failed and 21 ignored.
  [Combined Quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44412027994)
- **Studio** saved an edited page, reopened it in a fresh browser context,
  verified its text and 37 px styling, and exported it. The Core CLI packed
  the four files from the 1,474-byte ZIP and the production decoder verified
  their contents. Overwrite refusal and cleanup passed on Core `9b8f92ed` and
  Studio `db6cae98`. An earlier run timed out before it confirmed the reopened
  page. [Successful paired trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44368192079)
  · [Original failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44366437457)
- **Signed site recovery** passed on Core `7208e241` and Studio `2c5e4145`.
  The CLI signed a 1,204-byte, four-asset bundle with an ephemeral test
  identity. The daemon imported it with network roles disabled, was forcibly
  terminated, reopened its cache and exported byte-identical content. A second
  browser verified the signed local preview, the four assets and the security
  headers. The receipt confirms process, listener and private-state cleanup.
  [Signed recovery trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44368339229)
- **Publisher-offline retrieval** ran in the Debian 13 topology on Core
  `dc5a1bac`. The original publisher's service, PID and listener were absent
  before and after retrieval. A fresh client received all 2,097,628 bytes of
  a four-asset test site from one independent holder with zero origin bytes.
  The site's protected-route, HTTP and cleanup checks passed when validated
  against the retained artifact. The enclosing repair scenario failed because
  its earlier restart capture rejected five IGMPv3 membership-change records.
  The Silex export and browser rendering were exercised in the separate
  signed-site trial above.
  [Original topology run and artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44372819560)
  On `da018320` the complete repair and offline retrieval run passed. The
  independent holder retained nine chunks. A fresh client fetched all
  2,097,628 bytes from this holder and verified four HTTP assets and a range
  request with the publisher still stopped. All four network phases recorded
  zero forbidden packets and zero capture drops. The earlier repair restart
  recorded six mDNS leaves that matched the prior Linux group membership and
  its retransmission window. The fixture removed all owned objects and the
  guest host-state digests matched. The retained archive has SHA-256
  `e1a135092225929c005577203e41a8f03539a1483d726b7101793948d923a6ad`.
  [Successful full topology and archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44378301593)
  The first joined Silex-to-independent-Firefox trial stopped in strict Clippy.
  It flagged the length of the contribution test before any editor or guest
  started. The follow-up split signed test setup from the receipt checks.
  [Original joined trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44382248754)
  The follow-up joined the real editor, signed publication, independent peer
  storage and a fresh browser in one run on Core `20696912` and Studio
  `cb66fd7f`. Silex saved and reopened the edited page with its chart. The
  independent holder retained all nine chunks of the original signed export.
  While the publisher was offline, Firefox ESR 140.16.0 received all five
  files (2,358,929 bytes) from the holder, rendered the edited text at 37 px
  and decoded the 1024 × 768 chart. The origin supplied zero bytes. A 4,096-byte
  range request, guest state comparison and complete owned cleanup also passed.
  The original signed bundle SHA-256 is
  `7a8ca0a33db9854bda2045777b1ce2d6890e5bb150d72e6839e3261d099ccc1e`.
  [Joined Studio hosting trial and both receipts](https://github.com/VOLPAROSSA/volparossa/actions/runs/44384131952)
- **Owner-authorized site restoration** passed on Core `8b3d09a6`. The ordinary
  CLI activated a separately signed revision 3 that restored the exact bytes
  of revision 1 after revision 2. Replaying the same request confirmed the
  existing result and a competing signed candidate was refused. Reopening the
  owner's cache yielded the expected signed site. All three releases must be
  valid at activation. The result covers the local owner cache. Peer deployment
  remains a separate authorized operation. The streaming validator retained
  37 bytes of encoded index for a logical 256 MiB single-asset site. Its index
  bound is 262,148 bytes, in addition to chunk buffers and decoded metadata.
  [Passing restore and streaming tests](https://github.com/VOLPAROSSA/volparossa/actions/runs/44392313319)
  · [Earlier strict-lint failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44390773927)
  The publisher's `content contribute` and the reader's `content site open`
  now accept the exact reviewed manifest ID. The publisher rejected the
  original release when instructed to contribute its newly signed successor,
  even though the two releases authorize identical bytes. The reader refused
  older, newer and conflicting envelopes before opening the browser listener.
  The existing minimum revision and retained reader floor still apply. The
  hosted run on `69ba30e8` passed 68 focused tests, formatting and strict
  Clippy. Its isolated reader exercised the ordinary CLI and local HTTP
  listener with a test peer interface. The first run stopped when its
  isolated contribution test lacked the hosted namespace setup.
  [Passing paired selection tests](https://github.com/VOLPAROSSA/volparossa/actions/runs/44400389278)
  · [Initial namespace setup failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44399182634)
  A twelve-node Debian 13 trial on `060fcaa3` deployed an owner-restored,
  four-asset static site through the normal CLI. After a different revision
  2, the owner activated revision 3 for the bytes of revision 1. The
  publisher contributed the reviewed envelope without the signing key. An
  independent holder retained nine chunks. With the publisher offline, a
  fresh reader required the exact revision 3 manifest and received all
  2,097,628 bytes from that holder. The origin supplied zero bytes. All
  four HTTP assets and a 4,096-byte range passed. Cleanup left zero owned
  objects and the guest network-state digests matched. This generated-site
  trial exercised the HTTP viewer; the Silex and Firefox trial above used
  the original edited publication. The restored manifest ID is
  `df594173123ef0b495526c64b957ed9d1a1c118e8c5b1bef675fcd3f3a321b89`.
  [Restored-site deployment trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44400834835)
  · [Retained archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44400834835/artifacts/14473208812)
- **Core site tools** now stream assets to the output bundle and recheck their
  identity at read time. The CLI packed the maximum 256 assets with a process
  limit of 64 file descriptors. Its `content site confirm` command verified
  exact bytes and the final local-service receipt for an already signed site
  and rejected mismatched, interrupted and withdrawn responses. The combined
  Studio branch passed workspace tests, formatting and strict Clippy.
  [Core quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367875308)
  On `4b4dadaa`, `content contribute --input` verified an existing signed
  file through the same chunk handoff as an owner cache. The exact-signature
  contribution test, strict Clippy and all three quality jobs passed. Cargo
  reported 4,476 passed and 21 ignored. The later joined Studio KVM trial
  exercised the same contribution path in its normal CLI.
  [Signed-file quality run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44383997327)
- **Cloud** exercised owner uploads, restart and private catalog recovery using
  HTTP, OpenPGP and the pinned OpenCloud SDK. GnuPG sockets now work beneath
  long owner-directory paths. On `d105f983`, 111 Node and 13 Python tests
  passed locally. The cumulative upload branch passed 139 Node tests. These
  suites used a fixture for the peer Storage interface.
  [Main-derived change](https://github.com/VOLPAROSSA/volparossa-cloud/commit/d105f983555a6c15b2859e651e1e075647dcf2c6)
  · [Cumulative upload source](https://github.com/VOLPAROSSA/volparossa-cloud/commit/998bf2d46ba51ba904500e4f223d5f7d200092dc)
  The first paired VM trial ended during baseline import before the browser
  upload. A separate local reproduction found that encryption could complete
  and the helper would then fail while returning to an inaccessible inherited
  working directory. Both CLI helpers now enter a validated owner directory.
  All 139 SDK-backed Node tests and 14 Python tests passed locally on
  `178592a3`.
  [Initial VM failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44368961729)
  · [Corrected Cloud source](https://github.com/VOLPAROSSA/volparossa-cloud/commit/178592a3881d49f839f7716a154f7ef446ecbda5)
  On Core `94ba2fb8` and Cloud `178592a3`, the real OpenCloud Files UI
  uploaded 262,145 synthetic bytes and received HTTP 201. The fixture removed
  both local ciphertext copies and stopped one provider. A restarted browser
  and service downloaded the file twice. Baseline restores, exact charges,
  retirement of sixteen peer copies and zero remaining test objects passed.
  [Successful Cloud topology](https://github.com/VOLPAROSSA/volparossa/actions/runs/44374814775)
  · [Source bindings and receipt hashes](https://github.com/VOLPAROSSA/volparossa-cloud/blob/08f3d2551ed80372693df4a69fcef70eef67fa02/docs/OWNER_UPLOADS.md#owner-upload-and-recovery-on-18-november-2026)
  Cloud `720f88f2` adds the owner command `cloud-serve.mjs resume-upload`.
  After a browser lost its source file, a restarted owner process used the
  retained ciphertext and its existing journal to complete the pending upload.
  The OpenCloud SDK listed and downloaded the result. Repeating the command
  after completion made zero additional Storage calls. The tests rejected a
  wrong owner token, a changed grant template or ciphertext, and an absent
  journal. All 141 Node and 14 Python cases passed with a fixture for the peer
  interface. Recovery requires a previously persisted deposit journal.
  [Source, usage and test coverage](https://github.com/VOLPAROSSA/volparossa-cloud/blob/720f88f2a639ef5e2eecbba18c7bb2acb93f9645/docs/OWNER_UPLOADS.md)
  Core `83d49a7a` and Cloud `720f88f2` subsequently passed the joined
  owner recovery through the original OpenCloud Files UI and Firefox ESR
  140.16.0. Its single PUT was interrupted before HTTP 201. One of eight
  copies was committed, one was uncertain and six had not been attempted.
  The original file and browser profile were removed. Two owner resume
  commands reconciled the same journal, prior leases, ciphertext and catalog
  to the same ready marker. After removing both local ciphertexts and stopping
  provider A, a fresh browser downloaded all 262,145 original bytes twice.
  Deleting the upload and baseline cleared 16 copies. All three providers
  reported zero usage and leases, with matching before/after host state.
  This trial exercises explicit owner recovery. Background maintenance
  enrollment has its own acceptance below. Reproduce with `alpha-topology.yml`
  and `scenario=cloud-private-upload-resume` on the tested Core commit.
  The archive SHA-256 is
  `0c02c37e0ba9b3d4adf234f75d49077ae3c23db3b5479cce9bef7194d05760d9`.
  The original smoke report SHA-256 is
  `4740742d8d3fa4f11d7ffba41bd50fb38e9a59a8f4df362c15977bf8892c6dae`.
  [Interrupted browser upload and owner recovery](https://github.com/VOLPAROSSA/volparossa/actions/runs/44411591772)
  An independent run repeated the full interrupted upload, two owner resume
  commands, two cold Firefox downloads and deletion using the changes based
  directly on each project's `main`. Core `70430732` and Cloud `396d5d49`
  preserved the same journal, leases and ciphertext across restart. After
  deletion all three stores had zero leases, committed bytes and reservations.
  The public evidence archive SHA-256 is
  `82ee157d960cca4e2821d58984bfff46f0cab06fc46de29c591513f126709b40`.
  [Main-based native trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44416913278)
  · [Cloud change](https://github.com/VOLPAROSSA/volparossa-cloud/pull/26)
  · [Core integration](https://github.com/VOLPAROSSA/volparossa/pull/385)
  · [Original Core, browser and cleanup receipt](development/evidence/cloud-owner-resume-44416913278/cloud-private-upload-smoke.json)
- **Image** restored a private album into a fresh Immich 3.2.4 instance on
  Image `ef9b2260` and upstream `db355f79`. An authenticated client uploaded
  and read an 8,516-byte PNG. With the server stopped, Image encrypted the
  logical PostgreSQL dump and media, retained the owner's key separately, and
  removed the original Docker project. The 51,283-byte ciphertext restored
  into an empty database and fresh media volume. A new owner login confirmed
  the album membership and all original image bytes. Anonymous access was
  denied and the owned networks, containers, volumes and scratch were removed.
  The producer passed the ciphertext locally in this run. An earlier fixture
  invocation stopped after PostgreSQL restore on an unsupported Compose flag.
  [Real Immich restoration](https://github.com/VOLPAROSSA/volparossa-image/actions/runs/44410004375)
  · [Earlier attempt](https://github.com/VOLPAROSSA/volparossa-image/actions/runs/44409707182)
  · [Separate owner-key support](https://github.com/VOLPAROSSA/volparossa-image/commit/0da0c35e9372a828553f376c3eb404a6081e0bb8)
  The subsequent joined trial used that same Immich release with Core
  `46f5c2c9` and Image `ce16debc`. The source project and original
  ciphertext were removed. With provider A offline, the two surviving peers
  supplied two cold restores of the same 51,283-byte encrypted snapshot.
  Empty PostgreSQL and a fresh Immich instance recovered the owner account,
  private album and all 8,516 original photo bytes. Anonymous access was
  denied. After deletion of eight copies all three providers reported zero
  usage. The VM, Docker resources and private scratch were removed.
  Reproduce by dispatching `alpha-topology.yml` on the tested Core source
  with `scenario=image-immich` and `image_revision=ce16debc9277bdf80fa76c373746e3d502fc96fb`.
  The published two-file ZIP SHA-256 is
  `f467c00dfa0aa8036e52106d85961c67dc530ba53c39ce4b8e7d71a619036478`.
  Mobile synchronization and availability of a live service without an
  owner-operated server remain open.
  [Joined trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44411540175)
  · [Application receipt](development/evidence/immich-peer-44411540175/immich-restore-result.json)
  · [Storage receipt](development/evidence/immich-peer-44411540175/image-topology-receipt.json)
  A separate trial on the main-based Core `b3496f1b` and Image `fdbe8187`
  repeated both peer restores and the fresh database, album and media recovery.
  Both receipts bind the same new 51,283-byte ciphertext. The owner recovered
  the original 8,516-byte picture and anonymous access was denied. All eight
  copies were deleted and all three stores returned to zero. A preceding
  attempt stopped while acquiring the pinned release, before it started Immich.
  [Main-based trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44418787447)
  · [Application receipt](development/evidence/immich-peer-44418787447/immich-restore-result.json)
  · [Storage receipt](development/evidence/immich-peer-44418787447/image-topology-receipt.json)
  · [Earlier acquisition failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44415319470)
- **Mail** now connects from the browser and lets the account owner recheck
  a reported import after an interrupted metadata lookup. Chromium 154 exercised
  its actual form with a synthetic JMAP fixture. It performed one upload, one
  import and two readbacks for the exact same message. The earlier browser code
  failed before issuing its first request. Fourteen connector tests and 25
  Python source checks passed locally.
  [Mail development source](https://github.com/VOLPAROSSA/volparossa-mail/commit/650e96a56a77e0300a5aae7d36fa5db9233ab201)
  Thunderbird 157.0 then exercised the actual add-on using an isolated profile
  and loopback JMAP fixture. The first metadata request returned HTTP 503.
  After the user selected **Check stored metadata again**, the second request
  for the same ID succeeded. The fixture saw exactly one 165-byte message
  upload and one import. It removed its profile and stopped all test processes.
  [Native Thunderbird receipt](https://github.com/VOLPAROSSA/volparossa-mail/blob/fb1ba939bbec2833580f6b98c0aa071c7ed95786/third_party/thunderbird-extension-smoke.json)
  A follow-up joined that native Thunderbird interface to Stalwart Community
  with SQLite. Stalwart committed one 313-byte message. The fixture replaced
  the first metadata response with HTTP 503 on its way to the browser. A user
  recheck confirmed the same message ID. An independent download of the stored
  MIME matched all 313 original bytes. Profile and server cleanup passed.
  [Joined real-mailbox receipt and reproduction](https://github.com/VOLPAROSSA/volparossa-mail/blob/350c050e5b59c5205af837137de48058fa1f087c/third_party/thunderbird-stalwart-extension-smoke.json)
  Thunderbird subsequently closed normally after the owner imported the message.
  The original server returned the message after the client exited. The trial then
  killed Stalwart, confirmed its listener stopped and reopened the same SQLite
  database. An incorrect password returned HTTP 401. The owner retrieved the
  original message ID and all 313 MIME bytes. The receipt records one upload,
  one import and two metadata reads after the first response was replaced by 503.
  [Mail integration](https://github.com/VOLPAROSSA/volparossa-mail/pull/15) · [Native client and server receipts](https://github.com/VOLPAROSSA/volparossa-mail/tree/4406e3772d22762cae5fcaca6b5ed7b4cc840214/third_party/thunderbird-stalwart-mailbox-crash-recovery)
- **Chat** now emits a receipt event once per distinct message timestamp
  within one incoming encrypted Signal receipt. Separate envelopes and linked
  devices keep separate events. Three synthetic cases exercised the method
  from the pinned desktop receiver. The app also passed its 42 Python and 14
  existing Node tests. Peer delivery and the full desktop session remain open.
  [Chat receiver and test](https://github.com/VOLPAROSSA/volparossa-chat/commit/20b028db922142ef9772983211350fb8f44d56e2)
- **Weather** compares IFS and AIFS 2 m temperature forecasts against supplied
  public station observations on matched runs, grids and observation times.
  The CLI reports signed and absolute error, coverage and exclusions. Its
  synthetic fixture scores two of three times. A separate archive comparison
  at Berlin-Tempelhof for 11 October found a provisional 11.6 °C station
  observation and 24-hour forecasts of 10.73 °C (IFS) and 12.07 °C (AIFS).
  Both forecasts used the same grid point, 7.55 km from the station. The two
  archived fields were retrieved retrospectively. A skill comparison requires
  a broader set of forecasts and independent observations.
  [Archived fields, timings and station evidence](https://github.com/VOLPAROSSA/volparossa-weather/blob/f2c48306eefea26428cf94e1b2d2c5a54014752c/third_party/ecmwf-dwd-temperature-comparison.json)
  The NOAA cancellation fixture also checks that a live decoder child is
  joined. All 207 Node tests passed on the combined branch.
  [Weather source and usage](https://github.com/VOLPAROSSA/volparossa-weather/tree/ddb534f36c88206b06bc9bd938160418bd8d64cf)
  The ordinary Weather verification CLI now accepts archived GRIB fields and
  supplied public observations. For that same 24-hour forecast, it paired
  four provisional observations from Berlin and Potsdam across three model
  grid cells. Each model decoded each occupied cell once. The saved report
  reproduced byte for byte from the cached fields, and 212 tests passed on
  Weather `f850f74f`. These observations cover one nominal hour.
  [Runnable archive example](https://github.com/VOLPAROSSA/volparossa-weather/tree/f850f74f7347d121f039115afb6e5fb1d43e12f5#score-cached-archive-fields-with-the-verification-cli)
  · [Four-station report](https://github.com/VOLPAROSSA/volparossa-weather/blob/f850f74f7347d121f039115afb6e5fb1d43e12f5/third_party/ecmwf-dwd-archive-report.json)
  Main also includes the pinned decoder rebuild. Core `c7d65a4b` and Weather
  `05a7350c` reproduced the 14 source-built payload files (93,841,627 bytes).
  A separate Debian 13 guest verified all eight offline ABI checks, including
  isolated relocation and both ends of the CCSDS test field. The 97 public
  evidence files and both guest cleanups were independently checked. This
  concerns the Linux decoder ABI. Mobile sensors and forecast accuracy have
  separate evidence.
  [Native trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44412679519)
  · [Main integration and archive digests](https://github.com/VOLPAROSSA/volparossa/pull/350)
  A separate Debian 13 guest ran the ordinary Core helper, agent and Weather
  bridge with an owner distinct from the cache provider. A signed ECMWF
  forecast for Berlin was read twice across a bridge restart. The first HTTP
  read after its original signed expiry returned 503, 50 ms past the deadline.
  The direct Core read also refused the expired product. The Weather client
  had only loopback and the guest had no network card. The guest removed the
  original plaintext, stopped both services and left its scratch directory empty.
  [Weather run](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44427401562) · [Original expiry receipt](development/evidence/weather-cache-expiry-44427401562/result.json)
- **Map** clears an expired positioning-quality result when the Android
  activity or its window regains focus, and when a new assessment is requested.
  Eight synthetic Android/JNI emulator cases passed on `249266a8`, including
  a real dialog dismissal. The fixture removed its Android state and accepted
  its host-configuration checkpoint. The raw route/DNS/firewall comparison
  returned false. Physical sensors and navigation remain unverified.
  [Android trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44369696420)
- **Bank** accepts a TEST budget and a dated synthetic portfolio snapshot with
  an explicit source. The offline CLI gives whole units per asset, spending
  within aggregate ownership limits and remaining TEST cash. Nine library and
  four CLI tests, formatting and strict Clippy passed locally.
  [Bank source and runnable example](https://github.com/VOLPAROSSA/volparossa-bank/tree/29e79f9b9c5b3e4a83a80672580ee1c18276e526)

  The subsequent Bank integration staged an owner-signed TEST transfer, used
  Core's actual ordered store to commit it, reopened the store, and replayed
  the same receipt after expiry. The 100 synthetic units were conserved as
  balances of 30 and 70. The normal hosted command and 28 tests passed.
  This fixture supplies the transaction order locally. Network consensus and
  real financial settlement remain open.
  [Hosted example](https://github.com/VOLPAROSSA/volparossa-bank/actions/runs/44413979688)
  · [Bank main integration](https://github.com/VOLPAROSSA/volparossa-bank/pull/13)

  Four validators with separate stores subsequently executed the Bank owner's
  original signed commands. They moved 70 of 100 TEST units once. After the
  signing seed was removed and a validator restarted, both original commands
  were executed again at block 24. The receipt sequences remained 1 and 2,
  balances were unchanged and all four validators converged at height 25.
  The trial covered 3–1 and 2–2 partitions. Cleanup removed the private keys
  and namespaces and reaped the processes. The host observer accepted the
  observed lifetime countdown. Its raw snapshots differed.
  [Four-validator run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44426288636) · [Original build, consensus and cleanup receipts](development/evidence/bank-validators-44426288636)

### Native Firefox ordinary tabs

Core `50b92f8a` compiled Firefox 157.0.1 offline with Browser `c3311ebe`.
Both ordinary tabs verified the same 32 MiB body over two carrying MPTCP
subflows on distinct WireGuard paths. Releasing the first route at both ends
left the second transfer active. The origin observed the Exit address with no
proxy credentials. Firefox exited, its private profile was removed, the guest
network state matched and zero owned objects remained. Grant assignment in
this run used the privileged test driver. The preceding attempt stopped after
the first complete body.
[Passing build and KVM](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054)
· [Both trials and original receipts](applications/BROWSER_NETWORK.md#two-complete-native-firefox-navigations)

### Core project website — 2026-10-30

The bounded Golden Harbour introduction lives in `website/`, with an isolated
Python static build and project Pages artifact for `/volparossa/`. It imports
reviewed shared theme v1.0.3 from homepage commit `8114d966f3e9` and preserves
development/permission boundaries from Core source `edf569300acb`.
[Website verification](../website/VERIFICATION.md) records responsive Chromium/
Firefox renders, accessibility, no-JavaScript behavior and performance results.
This work changes no runtime or project goal and supplies no new Core, DPS,
network, model or sensor acceptance evidence. Publication follows the existing
required PR gate and the separate scoped website deployment workflow.
The owner’s subsequent visual refinement restores the four concept scenes below
the unchanged hero and adds an accessible rotating nine-application strip,
excluding Bank/Citizen; [bounded website evidence](../website/REFINEMENT-VERIFICATION.md)
records the responsive renders, original icons and interaction checks.
The final [Compute/satellite icon correction](../website/ICON-VERIFICATION.md)
replaces malformed custom geometry while preserving the page composition.

### F04 — helperacceptatie en integratie geslaagd — 2026-10-27

[PR349](https://github.com/VOLPAROSSA/volparossa/pull/349) is op 27 oktober 2026
gemerged als `edf569300acbdf5e7715b5192ffbb293235b15ab` en bevat de minimale
beveiligingsroute en de gerichte helpercorrecties. De mergegegevens zijn op
5 november 2026 opnieuw gecontroleerd; dit is geen nieuwe runtimeproef. De oorspronkelijke
[F04-evidence en failures](https://github.com/VOLPAROSSA/volparossa/blob/ff2df276bc50a395dbcfa2d11b515c51fe0ee340/docs/IMPLEMENTATION_STATUS.md)
blijven behouden; PR347 is historische basis, geen afzonderlijke integratiekandidaat.

De verkeersblokkade was een fixture-omgevingsfout: een verse private
netwerknamespace begint met ICMP-datagramgroepbereik `1 0`, terwijl de hook bewust
geen `NET_RAW` heeft. Correctie `3a4ef6c9` staat uitsluitend de gevalideerde
agent-GID toe in de twee tijdelijke namespaces die werkelijk ping uitvoeren.
Root-/groep-/capability-/namespacebinding, beginwaarde en readback zijn fataal;
productiecode en capabilities blijven gelijk. De initiële hostnamespace wordt
alleen gelezen; haar pingbereik is aan de bestaande voor/na-vergelijking toegevoegd.

De enige geautoriseerde [Debian13-KVM-proef40542366058](https://github.com/VOLPAROSSA/volparossa/actions/runs/40542366058)
**slaagt** op exact `3a4ef6c9d3499cbe4d71db614194cba14e3a89b6`.
De bestaande Client/Exit/Relay-ping-, handshake-, RX/TX- en relaygroeicontroles,
exacte custody/FD-storecycli, commit/destroy/retry, één geforceerde singleton
CleanupConfirmedExactPresent-restart, cleanup/retirement, hostvergelijking en
VM-/image-/bronfences zijn werkelijk doorlopen. Dit is de bestaande niet-bewaarde
branchproef; geen retained-main-mijlpaal, algemeen restartbewijs of DICN-productacceptatie.
Numerieke bereik-/counterwaarden zijn niet als afzonderlijke artifacts bewaard;
de positieve grens volgt uit de fatale guards en de exact gebonden PASS.

Zes nieuwe private-fixtureregressies, acht diagnosetests, de volledige betrokken
livecontracttest en gerichte syntax/ShellCheck/diffcontroles slagen. Onafhankelijke
bron- en resultaatreview bevestigt de afbakening. Eerdere Quality40487291792,
CodeQL40487286993, dependency/RustSec- en zbus/crypto/DPS-native-evidence blijven
hergebruikt voor hun gecontroleerd gelijke inputs; dit is geen herhaalde audit.
De geïntegreerde kandidaat behoudt de destijds actuele main-documentatie;
de [bestaande PR-controles](https://github.com/VOLPAROSSA/volparossa/pull/349/checks)
blijven bij hun geteste bron horen. De handmatige integratie is voltooid.
Dit bewijst geen nieuwe runtimecompositie en activeert geen productiefunctionaliteit.

### Development workflow — 2026-10-26

The remaining authored documentation has been reviewed across architecture,
network, services, development, privacy, applications and component references.
Repeated checklists and superseded trial narratives are consolidated; current
wire versions and runtime/installed-package claims are corrected against source
and existing evidence. Detailed records remain in the [documentation archive](archive/README.md).
This documentation work changes no product behavior or runtime acceptance.

The complete requirements now live in one GOAL, with DPS as a shared service and
Studio/hosting among the applications. Duplicate goal/prompt and add-on requirement
files are removed; source records live in the archive. The revised development
policy replaces fixed model/effort/role assignments with
task-driven selection supported by the current client. Effective requirements and
workflow are streamlined; original requirement snapshots and the evidence ledger
remain byte-identical. Preservation/reference checks and independent scope review
cover this change, not new runtime acceptance. Only the literal-document Rust test
is removed; behavioral tests and production paths are unchanged.

| Workstream | Recorded checkpoint; next boundary |
| --- | --- |
| Network | Two independent runners built identical Core and DNS worker packages at `428e2899`. Both passed A01–A15 and the Debian 13 install, upgrade and removal trial. One 32 MiB mixed-link transfer measured 1.437× the WAN-only throughput. The earlier trial measured 0.972×. [Acceptance and packages](#network-baseline-and-remaining-proof) · [Both mixed-link runs](https://github.com/VOLPAROSSA/volparossa/pull/439) |
| Storage / Image / Cloud | The real Immich album recovered from peer storage after one provider went offline. OpenCloud passed both direct upload and owner recovery of an interrupted upload before two cold browser downloads. An earlier combined run reached Image repair. The latest twelve-node trial reached Cloud publication after Image enrollment. The owner confirmed deletion for both applications, and each provider reported zero remaining leases and payload bytes. Joint repair and cold restoration remain open. [Storage trials](#storage-consumer-and-provider-evidence) |
| Protected Compute | Public two-turn execution and corruption rejection passed. A two-path trial authenticated the provider’s refusal when the protected device was unavailable. Hardware-backed private workload execution remains open. [Verified trial](#protected-compute-evidence) |
| Studio | The native Silex desktop saved a page with a unique visible edit, reopened it in two fresh processes and quit normally on protected Studio main. In a separate trial, Firefox rendered the signed Silex export from a holder while the publisher was offline. Joining the native desktop export to that hosting path remains open. [Native desktop](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44547586924) · [Independent hosting](https://github.com/VOLPAROSSA/volparossa/actions/runs/44384131952) |
| DPS / Map | On the real Monaco graph, synthetic signed traffic advisories changed a driving route from 1,083.24 m to 3,746.96 m. Expiry and replacement each restored the original geometry. The native desktop compared 1,489 expiry frames and 15 removal frames. Field positioning accuracy and mobile peer routing remain open. [Native traffic trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44539811197) |
| Cache / Weather | The Android 16 emulator and iPhone 16 Pro Max simulator each hid the expired ECMWF forecast, displayed a failed refresh and recovered after a second request. On iOS the source temperature was 7.115 °C. The four screenshots record the original display precision. NOAA remained available through the cycle. Physical-device validation remains open. [Android receipts](https://github.com/VOLPAROSSA/volparossa-weather/tree/3d1e6384a2ced86e3239598cac2173c5ff0696b8/docs/evidence/android-44514675704) · [iPhone trial and screenshots](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44542699817) |
| Code / Browser AI | Two tabs in a source-built Firefox each downloaded 32 MiB over protected connections. Detaching one preserved the other. The coding, cooperative job and protected inference trials have separate acceptance criteria. [Native browser trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054) |
| Transactions / Bank | Four validators preserved 100 TEST units across partitions, restart and replay. In a separate signed auction, independent readers can recalculate the indicative price from a frozen roster and fictitious limit orders. Full finality coverage, funding and external settlement remain open. [Validators](https://github.com/VOLPAROSSA/volparossa/actions/runs/44426288636) · [Auction reader](https://github.com/VOLPAROSSA/volparossa-bank/blob/6e234caf6d13eb37b58e192e57d52d2cc6c49fee/docs/PAPER_AUCTION.md) |
| Mail | The ordinary paired sender delivered 429 MIME bytes through two independent local provider stores. Stalwart lost its import reply and restarted. A retry found the same email and verified every byte before both providers acknowledged. A fresh Thunderbird profile opened its subject and body over implicit TLS. Public Internet receipt and protected multi-node Mail transport require separate trials. [Peer and Inbox receipt](development/evidence/mail-owner-44547309790/peer-mail.json) · [Complete Mail trial](https://github.com/VOLPAROSSA/volparossa-mail/actions/runs/44547309790) |
| Chat | Two standalone Signal Desktops exchanged a message while each correspondent was offline in turn. One Core client carried their traffic through the protected twelve-node topology to two independent providers. The recipient reopened its SQLCipher profile, the sender observed Delivered and both provider inboxes emptied. Separately, automatic delivery survived a worker restart on local provider sockets. [Protected transport and captures](https://github.com/VOLPAROSSA/volparossa/actions/runs/44538844389) · [Automatic delivery](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44548794182) |
| Citizen | An independent protected client received all 28,782 public referendum bytes from a peer with zero origin bytes. Citizen ran Belenios 3.3.0 offline on that exact ZIP and independently retained setups. The three fictional proposals were adopted, indeterminate and rejected. Real-person eligibility and recognized deployment remain open. [Peer retrieval and ballot replay](https://github.com/VOLPAROSSA/volparossa/actions/runs/44525516565) |
| Other applications / maintenance | Continue every agreed integration and organization-wide work; component/source checks do not complete consumer scenarios. |

### Execution priorities and next milestones

Choose complete executable slices by shared dependency, demonstrated failure and
system value; these priorities impose no fixed application/model/agent order.

1. **Storage.** Complete the cross-application Image and Cloud maintenance run
   through repair, cold restore, deletion and zero provider usage. Keep that
   multi-application result distinct from the successful direct Cloud upload.
2. **Protected model.** Build on the verified public resident session. Private
   execution requires separately authorized inputs and its own acceptance proof.
3. **Studio publication:** bound request geometry and Storage reads before
   allocations; separate untrusted editor/MCP preparation from trusted native
   review, identity/revision binding, signing and authorized contribution. Prove
   uncertain-handoff reconciliation, independent retention/retrieval,
   publisher-offline availability and rollback; continue shared AI/dynamic state.
4. **Consumers/platforms:** integrate real DPS/Map sensors, fusion/navigation and
   actual upload, Chat/Mail, Code/Browser and Weather scenarios through shared
   Core. Preserve existing offline/platform behavior and permission ceilings.
5. **Full goal and efficiency:** continue all layers, governance, transactions,
   authorized updates and applications. Optimize demonstrated repeated cost;
   keep runtime performance evidence separate from CI savings and respect the
   existing outreach, financial/legal, publication and host authority boundaries.

### Storage consumer and provider evidence

The Image-only trial on Core `46f5c2c98f49eeda1816517530961f2d8090657c` and Image
`ce16debc9277bdf80fa76c373746e3d502fc96fb` recovered a live Immich 3.2.4 album from three
Storage providers. The owner removed the source project and ciphertext, withdrew one provider,
and restored the 51,283-byte OpenPGP snapshot twice. A fresh PostgreSQL database and Immich
server returned the original 8,516-byte photo to the authenticated owner. Anonymous access was
denied. All eight fragment copies were deleted and final usage was zero at every provider.
The independently vaulted key stayed with the owner. [Run 44411540175](https://github.com/VOLPAROSSA/volparossa/actions/runs/44411540175) · [Immich receipt](development/evidence/immich-peer-44411540175/immich-restore-result.json) · [Core receipt](development/evidence/immich-peer-44411540175/image-topology-receipt.json)

The two retained JSON files are the original artifact contents. The ZIP SHA-256 is
`f467c00dfa0aa8036e52106d85961c67dc530ba53c39ce4b8e7d71a619036478`. To repeat the joined
trial on a selected Core ref containing the scenario, use
`gh workflow run alpha-topology.yml --ref <core-ref> -f scenario=image-immich -f image_revision=ce16debc9277bdf80fa76c373746e3d502fc96fb`.
The separate multi-application maintenance scenario is tracked below.

- **Integrated provider fixes:** PR327 merges close-before-log source
  `a41030a51471` as `157908ad1e4a`. Scoped run 39832609493 proves actual TLS
  session release under held event-log locks; ordinary Quality/CodeQL pass.
  PR331 merges provider event-drain source `c111114b65a5` as `2a15a7f114e6`;
  scoped run 39851344008 passes two queue units, five candidate cases, three
  negative controls, strict Clippy and host comparison. These controlled fixes
  do not establish the cause of earlier consumer stalls.
- **Consumer failure:** run 39837551972 on `a41030a51471` fails Cloud deposit
  (`CONTENT_UNAVAILABLE` at distinct TLS/route stages). Run 39855345985 on
  `7c569dd08a71` reaches `cloud_catalog_create/catalog_materialization_failed`;
  the API collapses peer restore, verification/decryption and local I/O, so the
  substage is unknown. Provider usage remains 6/6/4 leases and
  1,198,718/1,198,718/799,148 committed bytes with zero reservations. Local and
  coordinator cleanup pass; remote deletion and aggregate consumer cleanup do
  not. Image/Cloud fixture pins remain unchanged.
- **Integrated diagnostics:** PR334 merges as `a68b805a4a00` with passing Quality
  39857954009 and CodeQL 39857949804. Catalog restore diagnostic PR336, source
  `300766d9e822`, merges as `146cfe898e15`; Quality 39863841700, all CodeQL
  analyses and 66 Node tests pass. These source results do not prove catalog
  restoration. Failure snapshots are bounded/sequential, not per-request cause
  evidence; empty saturated rings do not prove absence of failures.
- **October failure and follow-up:** Alpha 39864473079 fails
  `private-storage-maintenance-core-restart`, specifically
  `baseline_custody/reconcile_progress/pending_handoff` with
  `replacement_retention_insufficient`. The retention guard correctly prevents
  deletion; a pending fragment can require its next renewal rotation. Consumer
  work is not reached. Reviewed PR339 at `145c49e35ac8`, tree `a0bc4b2eec1d`,
  preserves authority/custody behavior and drives the calculated ordinary turns.
  Its 93 inert smoke/44 wiring tests and real writer-to-bounded-reader controls
  pass. Recorded ordinary Quality 39871649767 and CodeQL 39871645927 pass;
  Quality tests merge `d78c02be1003`, tree `b6a107651409` (main `18b96ff3` plus
  source `145c49e3`), with 4,250 passed/0 failed/18 ignored top-level tests,
  334 focused Storage Python cases and 66 Node tests. Actual Alpha
  [39871646877](https://github.com/VOLPAROSSA/volparossa/actions/runs/39871646877)
  is now verified completed/failed at that source; its failed job step is
  `Require actual owner-private storage maintenance`. This metadata does not
  establish the underlying failure substage, rotation convergence, catalog
  restoration or independent remote cleanup.

PR371 restored bounded ordinary renewal rotation and validated failure
diagnostics. On PR279 at `2a8b4fdff5eec755cbad14998d2411f54c066cbe`, Quality
passed the Storage contracts, build and integration tests, and their shared gate.
Its test merge `1485ae3c` has the same tree as that source. CodeQL also passed.
[Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/42147777520) · [CodeQL](https://github.com/VOLPAROSSA/volparossa/actions/runs/42147771678) · [Earlier Storage runs, pins and artifact digests](https://github.com/VOLPAROSSA/volparossa/blob/2a8b4fdff5eec755cbad14998d2411f54c066cbe/docs/IMPLEMENTATION_STATUS.md#storage-consumer-and-provider-evidence)

The 18 November trial at that same source failed during Image publish. Core
maintenance reached cursor 9, restored twice and deleted all eleven copies.
Three independent provider readings then showed zero reserved bytes, committed
bytes and leases. Image later received `CONTENT_UNAVAILABLE` on fragment 2,
copy 0, during APPEND. Opening the stream reached `flow_acquire` and recorded
three rounds. The first failed with `helper_kernel` and the last with
`helper_cleanup_incomplete`, both at `helper_acquire`. Cloud did not start.
[Run 44301340772](https://github.com/VOLPAROSSA/volparossa/actions/runs/44301340772)

A separate phase-wide observer recorded `mptcp_connect_poll_timed_out` first
and `acquire_coordinator_unavailable` last across three attempts. The record
has no application, fragment, copy or provider identity. The helper log separately
reported a bind failure (errno 98) and two poll timeouts. The cause of the
Image request failure remains open.

The guest host-state comparison passed, and local fixture cleanup left
zero owned objects. Consumer providers A, B and C still held 3, 3 and 2 leases
respectively. Their committed bytes were 599,359, 599,359 and 199,787. C also
held 199,787 reserved bytes. Remote consumer deletion and owner reconciliation
remain open. The retained ZIP has SHA-256
`5b4303e602b2ec8b6541cdc93b64421ae010b4b64c12f7858d8bf7bab77ea95b`.
[Trial artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44301340772/artifacts/14428484479)

Two further hosted trials restored the Core archive and deleted all eleven copies.
Each recorded zero leases and bytes at the three Core providers. On `8ae10f21`,
Image FINALIZE waited 90–120 seconds for the challenge length on fragment 2.
On `43e9027e`, Image RESERVE on that fragment hit the TLS deadline for copy 0
and helper cleanup was unconfirmed during stream acquisition for copy 1.
The helper independently recorded `lease_expired` during the publish phase.
The same route had already served the preceding Core phases for over 561 seconds.
The log cannot link that expiry to a particular copy. Cloud did not start.
Consumer providers retained eight leases in the first trial and six in the second.
[First trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44313217738) · [Second trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44315089745)

The second source bounded the worker connect poll by the five-second cap and
the original request deadline, reserving 250 ms to return the result. It also
reduced the failed-consumer sampler to one final snapshot. The inert incomplete-flow
fixture used eight control queries, down from 104, and preserved the original error.
The next revision also caps a connected client MPTCP acquisition at the registered
worker lease expiry before dispatch. The caller's earlier deadline takes precedence.
The remaining acceptance check is Image and Cloud publication, restoration after
provider withdrawal, deletion and independent zero usage through route turnover.

On `ff268f3e`, the trial stopped earlier. The foreground `storage peer progress`
command exited while the maintenance turn was marked `working`. The receipt
contained no cause for that exit. The fixture now requests a diagnostic from
that same call and can retain its exit status, typed operation stage, error
category and bounded agent code. A failure outside a known stage is recorded
as `unknown`. Image and Cloud were not reached in this run.
[Foreground trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44332080434)

On `49955656`, foreground progress succeeded. Core restored twice and deleted
all eleven copies. Each Core provider reported zero leases and bytes. Consumer
publication then stopped at `cloud_catalog_create/catalog_materialization_failed`.
The catalog's single Storage restore returned verified and complete. Consumer
providers A, B and C retained 6, 6 and 4 leases.
[Catalog trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44341178239)

Without a user runtime directory, the Cloud catalog's private GnuPG socket
would use a 105-byte path. The pinned helper allows up to 103 bytes. The
fixture now uses a 102-byte catalog socket path and checks it before consumer
publication. The trial did not record which runtime directory GnuPG selected.

The next [catalog trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44348799240)
at `5186411b` failed during Cloud catalog creation. Its bound restore returned
`retained_operation_incomplete` with both Core operation completion and restore
verification false. Providers A/B/C retained 6/6/4 leases with zero reserved
bytes. Guest cleanup and host comparison passed. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44348799240/artifacts/14452602822)
has SHA-256 `d0a3e132d6cfc0402e63db407b01cc36e7310e0e3cd7d2896712b3e5ddfb8abf`.
The copy and transport cause of this restore failure are unknown.

Foreground restore now shares one retry per copy across its Progress preflight
and verified range reads when the agent reports a provider TLS handshake deadline
before READY. The retry keeps the existing exchange deadline, offset and grant.
Background turns and ordinary successful flow counts are preserved.

At `edf778da`, [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367731858)
passed, including the live framed restore lifecycle. The
[KVM trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367739602)
completed Image and Cloud publication, including Cloud catalog creation and the
56-flow publication gate. Both applications committed eight copies and
1,598,292 bytes each. The run then failed at `exercise/image_repair/private_file`.
Independent readings found 6/6/5 provider leases with zero reserved bytes.
Scoped local cleanup and the guest host-state comparison passed. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367739602/artifacts/14459484719)
has SHA-256 `ab571e82f420c93df74883d07268a6140aa673ece20f2d6777a70af9d17421f3`.
The report does not record the inode or attribute that tripped the private-file check.

A deterministic fixture regression reproduces the same error when the replica
writer renames a new manifest after the observer opens the old one and before its
first stat. The observer now discards an otherwise valid private inode with zero
links so its existing bounded poll can reopen the current path. Multiple links,
wrong ownership or mode, and invalid file size remain fatal.

The [assembled trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44375959400)
at `c6a810a8` passed the 56-flow publication gate and both applications committed
eight copies each. Exercise stopped at `image_repair/application_failed`.
The three stores held 6/7/6 leases and zero reserved bytes. Local cleanup
and the guest configuration comparison passed. All-copy deletion on this
maintenance run remains unverified. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44375959400/artifacts/14463864552)
has SHA-256 `e54fbdd7eac7d52beeead56af4a644e935038ec8bedfeec72b541acd605a466e`.

The Image fixture now observes repaired membership before the foreground
restore, which supplies the verified post-read accounting. This removes an
extra status command that would pause and restart the active owner before the
actual read. Owner startup, repair observation, restore, decryption and final
join report separate stages. A closed exercise error survives subsequent owner
teardown. The earlier generic error does not identify which call failed.

[Run 44385364109](https://github.com/VOLPAROSSA/volparossa/actions/runs/44385364109)
at `8e156da3` stopped in the source-contract step before VM preparation.
The Image wiring test's isolated shell selector lacked the empty default for
the newly integrated optional Studio evidence digest. The complete guest driver
already initialized it. The test now supplies the same empty default.

The next [maintenance run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44387064217)
passed preflight and ran on `ac51c47a`. Three Cloud deposit reservations
failed before a protected stream was available. The corresponding requests
for fragment/copy (1,0), (1,1) and (2,0) each recorded eight flow acquisition
attempts with `helper_kernel` at both ends of the summary. A separate phase
sample observed a socket bind error and a poll timeout. Its records cannot be
assigned to a particular copy. Providers A/B/C still held 6/5/2 leases with
zero reserved bytes. Local cleanup and the guest network-state comparison
passed. The run ended before the Image repair and all-copy deletion stages.
[Retained archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44387064217/artifacts/14470925130)
SHA-256 `8b37f49942e02d42f8be595c78f3b9fffd896066ecdc1b68da17a7b13c70d543`.

The opt-in fixture on `b037a998` distinguishes an authenticated client MPTCP
bind rejection (`EADDRINUSE`) from a connect poll timeout. The ordinary
application still sees the same kernel failure category. The first hosted
attempt on this revision passed its source checks, then stopped before VM
startup because the runner's APT index offered no QEMU package. It produced
no guest report. In the separate workspace quality run, strict Clippy flagged
a narrowing cast in the 256 MiB site-layout test. Revision `53027324` uses
a checked conversion for the block length.
[Initial runner setup failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/attempts/1)
· [Original workspace check](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397448406)

[Attempt 2](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/attempts/2)
installed the packages and ran the twelve-node KVM trial on `b037a998`.
Cloud again stopped before READY on the same three deposit reservations.
Both copies of fragment 1 recorded eight connection attempts. Copy 0 of
fragment 2 recorded seven, ending with `helper_other_rejection`. The source
maps that final category to an unconfirmed acquisition and ends the retry
loop. The app recorded no deadline for these requests. The fixture retained
a poll timeout for one exchange. The separate helper
log also recorded a bind rejection. The available records do not establish
which copy experienced either event or the causes of the intermediate attempts.
Providers A/B/C retained 6/5/2 leases with zero reserved bytes each. Local
cleanup and the guest network-state comparison passed. The combined trial
did not reach repair, cold restore or all-copy deletion.
[Retained second-attempt archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/artifacts/14475421816)
has SHA-256 `47a1dbe1618480fb88f7e065a3769b70011cccf906e21b098c2177265a825a53`.

The [next twelve-node run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44409967365)
on `ed1764f6` stopped during Image deposit. The original request for
fragment 2, copy 0 hit a provider TLS handshake deadline before the agent
reported READY for Append. The reservations for (2,1) and (3,0) each
recorded eight flow acquisition attempts, with kernel errors on the first
and last attempts. Reservation (3,1) returned `CONTENT_POLICY`. The
helper recorded a bind rejection without a binding to a particular copy.
The three stores had 1/2/2 leases, 199,787/399,574/199,787 committed bytes,
and 0/0/199,787 reserved bytes. The guest removed its local fixture and
owned processes and its host-state files matched. This run did not reach
Cloud publication, repair, cold restoration or acknowledged remote deletion.
[Original evidence archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44409967365/artifacts/14480386650)
SHA-256 `a5895c3e122b8559b9703b1bb0b3b9482c90152668cd5b4e850938ae7541a1e4`.

The foreground deposit now allows one new TLS handshake per copy after a
correlated timeout before READY, within the original exchange deadline.
The framed owner/provider test reopened its original journal after losing the
first Reserve confirmation. It retained the first acknowledged chunk, rejected
a subsequent authentication failure, completed the original lease and read the
exact bytes back. Deletion returned provider use to zero. The test used the
real SQLite provider and a controlled local IPC transport. It passed in the
default-branch change's workspace suite (4,459 passed, zero failed, 21 ignored).
[Core integration](https://github.com/VOLPAROSSA/volparossa/pull/386)
· [Quality and test log](https://github.com/VOLPAROSSA/volparossa/actions/runs/44418876629)

The next twelve-node trial on `462581e2` prepared Image and Cloud. Image
publication stopped at fragment 2, copy 0. The owner had yet to send a signed
Reserve. The agent spent 90–120 seconds awaiting the response frame length for
the provider challenge and exhausted its operation deadline. The error report
does not establish how many length bytes arrived. Separate fixture records
observed a provider TLS timeout without identifying the affected copy.
The Image adapter closed. The later owner deletion returned an incomplete
result. Independent reads found zero leases, reserved bytes and committed
bytes at all three providers. Local cleanup removed 40 files and 20 directories,
and the host snapshots matched. Cloud publication and combined repair were
not reached. The 82,243-byte Actions ZIP has SHA-256
`12cfd2f78bce34895487d6fb9e116eef7f33adc4c86b8e3f6891928ec8838b56`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44419915713)
· [Original failure, usage and cleanup reports](development/evidence/storage-maintenance-44419915713)

The twelve-node trial on `9335306b` completed the separate Core lifecycle and
deleted all eleven Core copies. The consumer phase prepared two encrypted inputs
of 799,146 bytes each and passed Image enrollment. Cloud stopped during deposit.
Its fragment 0 FINALIZE (copy 0) and RESERVE (copy 1) each made eight attempts
to acquire a protected stream before READY. Both reported `helper_kernel` on
the first and last attempt. A separate RESERVE on fragment 1, copy 0 returned
`CONTENT_POLICY`. The helper logged one MPTCP poll timeout. The phase observer also recorded a
generic transport-unavailable response. Neither observation identified a fragment or copy.

During failure cleanup, the owner confirmed deletion for both Image and Cloud.
Before the private journals were removed, all three providers independently
reported zero leases, reserved bytes and committed bytes. The disposable guest
removed its fixture state and both host snapshots matched byte for byte.
Cloud publication stopped before joint repair, cold restore and the final
acceptance checks. The 82,290-byte ZIP has SHA-256
`a3870f4a6ab880537cb1e8752f3d64c569579f71e5cdb7415378ce1f2c0590e8`.
[Original run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44430761553) · [Original application, route and cleanup receipts](development/evidence/storage-maintenance-44430761553)

On `b856970b`, the twelve-node trial deleted all eleven standalone Core copies
and prepared both 799,146-byte encrypted application inputs. The Cloud CLI
reported one failure during deposit. Its reserve for fragment 1, copy 1
returned `CONTENT_POLICY` while waiting for agent READY. The protected
stream acquisition log projection was empty. The incomplete fixture sample
included a provider C selector-read error and had no fragment or copy binding.
Both owners confirmed deletion. All three providers independently reported
zero leases, reserved bytes and committed bytes. The host snapshots matched.
Combined repair and cold restoration remain open. The original 81,804-byte
Actions ZIP has SHA-256
`38468903864d1f287f161674cfcc4fd1901a92bacef266cc940bd6e39eca8b14`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44440163724) · [Original application, sample and cleanup receipts](development/evidence/storage-maintenance-44440163724)

In the following twelve-node run at `e5d06b21e87409139d78317dc7deeae6b372b51b`,
Image stopped during publication. FINALIZE on fragment 2, copy 0 reached the
initial READY boundary with a TLS handshake deadline. RESERVE on fragment 2,
copy 1 and fragment 3, copy 0 each reported eight helper-kernel acquisition
rounds. Fragment 3, copy 1 reported three rounds, from helper-kernel to another
helper rejection. All four foreground failures carried `CONTENT_UNAVAILABLE`.
The separate incomplete sampler observed a two-sided TLS timeout at provider C.
Its samples carry no fragment or copy identity. Image confirmed owner deletion.
Cloud had no archive. All three independent provider measurements showed zero
leases, reserved bytes and committed bytes. Local cleanup completed and the
guest's outside-namespace network snapshots matched. Joint maintenance and
cold restoration remained pending. The preceding run reached Cloud before it
stopped. The 82,262-byte archive (artifact `14496173050`) has SHA-256
`95205102709774ce80e5a7df56fc85121e399b3aa4a2d00744ae8fc5c72a50dd`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44447515035) · [Original application, samples and cleanup receipts](development/evidence/storage-maintenance-44447515035)

The next twelve-node trial on `cf93b5a2` completed the independent eleven-copy
Core lifecycle. Image then reported one failed deposit operation, with zero
omitted failures. Its owner submitted FINALIZE for fragment 2, copy 1. The
agent reached the operation deadline while reading the provider receipt.
The helper recorded zero acquire samples. Provider event sampling reported one
request I/O failure before identifying an operation, with no fragment binding.
The provider's state at the time of that timeout remains unknown.
Image subsequently confirmed owner deletion, Cloud had no archive, and the
three provider stores each showed zero leases and zero reserved and committed
bytes. Guest host-state digests matched. The combined repair and cold
restoration still need a completed joint run.
[Original archive, SHA-256 `0f4afc3c…19c0f23`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44455715673/artifacts/14499901605) · [Original application and cleanup reports](development/evidence/storage-maintenance-44455715673)

The separate upload-continuation VM on the same Core revision also stopped
during shared Image publication. Its only failed operation was APPEND for
fragment 3, copy 1. The agent returned `CONTENT_UNAVAILABLE` during control
selection, before READY. The owner confirmed Image deletion. Cloud had no
archive, and the upload continuation did not start. The independent Core test
deleted all eleven copies with zero payload charge. The guest removed its
owned fixtures and its before/after network digests matched. This run has no
consumer provider-usage snapshot for the failed Image deposit.
[Original 81,532-byte archive, SHA-256 `8e6123b1…ce80bc75`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44514676250/artifacts/14527619866) · [Original reports](development/evidence/storage-maintenance-44514676250)

On `bb48e128` the shared publication reached Cloud. Its only failed operation
was RESERVE for fragment 3, copy 0. The agent returned `CONTENT_UNAVAILABLE`
during stream opening with local route state as its reason. The provider had
received no signed reservation on this connection. A separate helper sample
recorded a bind error (errno 98) without a matching request identity. Both
owners confirmed deletion. Providers A, B and C independently reported zero
leases, reserved bytes and committed bytes. The eleven-copy Core lifecycle and
guest cleanup completed. The guest's before/after host-state digests matched.
[Original 81,981-byte archive, SHA-256 `cfb1313c…8bb5e46`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44516433050/artifacts/14529597943) · [Original reports](development/evidence/storage-maintenance-44516433050)


#### Automatic upload integration candidate

Upload profiles 1–6 retain their application pins and finite authorization
ceilings. Before upload profile 6 can run, shared consumer profile 10 must pass
the full Image and Cloud lifecycle with verified cleanup and zero usage on all
providers. The run also requires TLS-close diagnostic 9. Consumer profile 10
pins Image `f51b8ace` and Cloud `5f143725`. Upload profile 6 pins Image
`1e812ec6` and Cloud `35598609`. Each phase checks its own source and preceding
receipt. Quality covers the reusable upload checks and two isolated TLS-close
contracts. Both upload export paths validate the two diagnostic sidecars.
[PR279](https://github.com/VOLPAROSSA/volparossa/pull/279) · [Original candidate](https://github.com/VOLPAROSSA/volparossa/blob/dd1fd4dff55413ade4cfb26ffcb7bf5a9ad26c01/docs/IMPLEMENTATION_STATUS.md)

The joined trial must demonstrate authenticated upload, automatic enrollment
under finite authority, provider withdrawal, repair, two cold restorations
across restart, deletion and cleanup. That trial remains pending.

### Protected Compute evidence

The public resident model completed two turns on `6ac9f2a8`, and PR332 merged
as `f355776a` with the same tree `a62dc47706d7b299fc59cf9652192cc5288c4340`.
The requester received `READY` and `4` in order, retained the session between
turns and removed each request’s files. At shutdown it reaped the child and
removed private session state. VM, tool and scratch cleanup all passed. The
corrupted image failed at `verity_read` before entrypoint invocation.
[Merge](https://github.com/VOLPAROSSA/volparossa/pull/332) · [Public trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/42145544662)

In a separate twelve-node guest on `d375bf79`, the requester selected two
MPTCP paths and received an authenticated refusal of its versioned
guest-key confirmation request. The provider reported that the protected
device was unavailable. No worker was admitted and no private input was
released. The network observer, host checkpoint and VM cleanup passed.
A positive hardware appraisal and a private inference result remain open.
[Protected-quote run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44425796022) · [Original route and VM receipts](development/evidence/protected-quote-44425796022)

The host configuration checkpoint accepted a change in IPv6 reference metadata.
The raw IPv6 route fingerprint changed. IPv4 routes, resolver configuration and
IPv6 non-reference-count fields matched. All eleven execution receipts were
verified in public artifact `13472243011`, SHA-256
`15663a652423a85056eb7879ff30edd7b66048d12f42af8a4681f039ebb6b6e5`.
Confidential execution, hardware attestation and independent guest-key origin
remain open.

The controller now stages the complete result in the private evidence directory.
After cleanup, it blocks its three cancellation signals, checks its deadline and
takes a pending-signal snapshot. A cancellation already handled or pending at
that snapshot prevents success. A later signal cannot reverse the decision.
An atomic link publishes the complete receipt only if the final name is unused.
Synthetic writer tests exercise these boundaries and preserve existing evidence.
The public inference result above belongs to its original revision.

A fresh public model trial on `82c3e068` exercised the result writer from
`88406999` with the accepted execution recipe restricted to its own branch.
Both requests returned their expected outputs, `READY` and `4`. The requester
retained the session between requests, then reaped the child and removed its
private state. The corrupted image failed `verity_read` before the entrypoint.
The VM, tools and scratch data were cleaned up. The host configuration check
passed with a raw difference in IPv6 reference metadata. The two source and
runtime artifacts were checked independently. The execution ZIP SHA-256 is
`9a16964f34facde0d3a4dd5e046eef7f119e935b030df06d1eeded48cbbd5f19`.
The trial used public inputs. Confidential hardware attestation and private
network inference remain open.
[Updated public model trial and receipts](https://github.com/VOLPAROSSA/volparossa/actions/runs/44383609439)

The resident workflow consolidates three historical wrappers. Source validation
passed 143 Rust tests, two documentation tests and 729 Python tests. For an
explicit public trial, use the reviewed commit on
`integration/resident-model-main-20261022`. Earlier host-check failures,
source-only runs and their exact revisions remain in the historical record.
[Workflow](../.github/workflows/protected-resident-model.yml) · [Source checks](https://github.com/VOLPAROSSA/volparossa/actions/runs/42141349016) · [Prior evidence](https://github.com/VOLPAROSSA/volparossa/blob/f355776a9191ce5ade255cc299b765229e9f5e99/docs/IMPLEMENTATION_STATUS.md#protected-compute-evidence)

### Studio and shared hosting evidence

Paired actual [39869460125](https://github.com/VOLPAROSSA/volparossa/actions/runs/39869460125)
passes on Core `dfa6f3434bb9` and Studio `eaf9e336e003`: real editing and
37px styling/preview produce a 1,477-byte DownloadConnector ZIP; actual Core
packing/decoding verifies four assets, lengths, hashes and edited HTML/CSS.
Packing again into existing output is rejected. In-memory model serialization
preserves edits; saved-project reload is not proved. Scoped browser/server and
temporary-output cleanup pass, without a complete host-absence audit.
Studio PR2 merges as `bb89a781d56f` with the exact tested Studio tree;
Core PR330 merges as `18b96ff3ab50`, with separate combined-tree checks.

Expected-publisher guard PR337, source `35c9209b280d`, merges as
`b15559129bc5`. Quality 39865075626 and CodeQL pass its source: signer pin
mismatch is rejected before manifest/cache/signing/contribution side effects.
CLI peer receipts are simulated, not independent hosting. Full native review,
bounded export preparation, identity/revision authority, independently retained
hosting, shared AI and all fifteen Studio acceptance cases remain open.
The pinned publication route currently builds vectors and reads Storage assets
before calling the connector; preparation must be bounded before that seam.

PR340 adds optional expected-input SHA-256 binding over a bounded owned,
zeroizing snapshot, publishing the same captured bytes and rejecting before
credential/cache/signing/IPC effects; omission preserves streaming behavior.
Initial Quality 39873065947 fails Clippy on test binding names; correction
`4c0e11a2b349`, tree `6802c497e899`, only renames that binding. This prerequisite
does not establish native review authority or hosting.

The subsequent local-viewer fixture uses Core PR342 `c815483c48e5` and Studio PR4
`65ab59b81b3c`, with an explicitly mocked local named transfer into actual
`content site open`; it is not independent peer hosting. Recorded actual
39875855784 fails `viewer-runtime/exit_nonzero`: editor/export and Core viewer
compilation pass, owned groups drain and temporary outputs are removed, but
no successful viewer, child-control or independent-browser result follows.
Its reviewed bounded diagnostic follow-up pairs Core `81ecc1a79561` with Studio
`164e08dfa487`; 13 inert diagnostic tests pass. Run
[39877380401](https://github.com/VOLPAROSSA/volparossa/actions/runs/39877380401)
is now verified completed/failed at that Core SHA in dependency acquisition/Studio
fixture compilation; the actual viewer/browser step is skipped. These metadata
localize that follow-up's reached step, not the earlier viewer failure's cause.

[Studio evidence, failed trials and source bindings](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#studiohosting-scope-and-preserved-work--2026-10-22)
and the [PR343 supplement](archive/integration-evidence-pr343-20261023.patch.txt)
retain artifacts, hashes and exact source/tree bindings without becoming routine
startup context.

### Decentralized positioning system — 2026-10-21

Core DPS service PR299, dormant-daemon proof PR305 and quality-only C ABI PR314
are integrated. Envelope 2 / DPS schema 1 uses field 64, preserving Storage's
46–49 / 34–37 assignments. The 36-byte quality ABI accepts canonical bounded
protobuf, returns no coordinates and grants no sensor/application authority.
Synthetic daemon execution, joined normal shutdown and bounded unchanged host
observations are proved, not hardware positioning or crash/restart recovery.

Map actual 39844370003 at `1546bf3ada1c` passes eight actual Android/JNI cases,
offline rebuild, owned cleanup and cancellation controls. The completed-emulator
configuration checkpoint is accepted; raw aggregate
`host_routes_dns_firewall_unchanged=false` is retained. The runner is
`7.0.0-1017-azure`, so the separately researched 6.17 profile remains unexercised.
Vendor patch lineage, physical positioning, sensors, main navigation and
application identity/permission authority remain unproved. The fixture stack
enters Map main as `ae7a5ccdbd14`, documentation as `8a227709e99f`.
Preserve unpublished Map `feature/native-traffic-lifecycle` at `ca7a4e59a057`.

[DPS/Map history](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21)
and the [service contract](services/DPS.md) retain research and acceptance detail.

### Map, Weather and application evidence

On Core `8ca8522c` and Map `f965604d`, an independent provider delivered all 325 signed bytes to the Linux Map adapter. After disconnect, the owner reopened the same bytes with zero peer traffic. One second after signed expiry, the adapter refused a new handoff. The host snapshots matched. The road graph in this trial was synthetic. In a separate Android 35 emulator, two cold launches of the original Organic Maps app calculated walking routes of 390 m and 490 m using the Monaco map package in airplane mode. The subsequent desktop trial used a separately seeded signed feed on the real Monaco graph. The joined mobile path remains open. [Peer traffic trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44438057954) · [Organic Maps trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44444481182)

Two cold Drizz.li builds produced identical bytes for all 97 tracked files. In the browser trial, the expired ECMWF publication returned HTTP 503. Drizz.li then displayed 9 °C from signed revision 2. Overmorrow passed all 24 Flutter tests in three independent release builds. All 64 output files matched in relative path, mode and content, totalling 24,608,666 bytes. Physical devices and iOS remain open. [Drizz.li build comparison](https://github.com/VOLPAROSSA/volparossa-weather/pull/41) · [Forecast refresh](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44445914018) · [Overmorrow comparison](https://github.com/VOLPAROSSA/volparossa-weather/pull/44) · [Third build](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44447940253)

The original Silex dashboard ran in Chrome against its Rust server. The operator created, renamed and duplicated a project. After restarting the server and browser, the dashboard listed both projects and the operator deleted them. A separate build produced the native 34,281,248-byte Silex executable. Native WebView execution and publication authorization remain open. [Dashboard trial](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44445227423) · [Native build](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44444745137)

Signal Desktop processed delivery receipts for two simulated encrypted peers. After reopening its SQLCipher database, three intended receipts still showed delivered, the cross-recipient control still showed sent, and the four message IDs matched. In a separate Citizen trial, the upstream Belenios verifier and public replay checked the encrypted ballots, decryption and totals for three fictional referenda. Four yes votes among six eligible residents adopted the proposal, four no votes rejected it, and three yes with one abstention left it undecided. [Native Signal run](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44435698764) · [Offline Belenios run](https://github.com/VOLPAROSSA/volparossa-citizen/actions/runs/44434956603)

Signal Desktop exported a 198,352-byte encrypted backup. When two of three Storage providers went offline, two of four fragments remained readable and the owner received no partial output. After one provider returned, the owner recovered all four fragments and imported the original backup in Signal. All three providers reported zero remaining usage after cleanup. [Native Signal and Storage trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44444982433)

With Thunderbird closed, the owner’s Stalwart server accepted a second message over local SMTP. It rejected an unknown local recipient and external forwarding. After Stalwart restarted on the same SQLite database, the owner recovered both the original import and the delivered message, including its stored transport headers. This exercised an isolated loopback mail server. [Source-bound Thunderbird and Stalwart receipts](https://github.com/VOLPAROSSA/volparossa-mail/tree/5bb90ec3be8c168fd58a19e2d03f626f6560d96b/third_party/thunderbird-stalwart-owner-smtp)

### Latest completed integration evidence

- **Code:** actual 38824828727 on Code `fd4ff9688c58` / Core `7d0f9f0b492c`
  completes two reads, approved edit/test, independent verification and scoped
  cleanup with real native model output. Code PR11 is integrated. Core PR277
  separately integrates its native-only backend; that main composition has no
  new model trial. General coding quality/performance, native editor and
  protected peer execution remain open.
- **Weather/cache:** Drizz.li 38228710535 and Overmorrow 38241212407 prove actual
  protected acquisition and initial/refresh UI behavior. Installed Android
  38717988016 passes actual app-triggered delivery, cache refresh and
  background/resume on Core `aac5be7f` / Weather `3b90442a`. The separate offline Debian trial 44427401562 now covers real cache expiry.
  Physical devices, iOS and full source/feature coverage remain open.
- **Transactions:** actual 37669796654 on `2ea504e399eb` passes four-validator
  TEST conservation/conflict, 3–1/2–2 partitions, rejoin and committed-retry
  replay. Raw parent snapshots differ; the separately bounded expiry-countdown
  observer accepts the represented changes, not continuous unchanged-host
  proof. Full distributed finality/Byzantine/pre-commit crash coverage, external
  settlement and complete Bank functionality remain open.

These results remain bound to their actual source and scenario.
[Earlier completed integration details](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence)
and [Transaction evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#bank-and-transaction-layer-implementation)
include independent review, resource limits, artifacts and unresolved cases.

### Retained branches and resumption dependencies

The owner-designated central build chat maintains the current work across repositories. The organization queue links to the open work and the protected project goal records its mandate. For local checkout paths, use `git worktree list` in the selected repository. [Organization maintenance](https://github.com/VOLPAROSSA/.github/blob/main/MAINTENANCE.md) · [Project goal](development/GOAL.md)

The automatic upload candidate continues in Core #279. The resident model trials retain their source-specific workflow revisions and original outcomes. The October index preserves the earlier branches, machine-local paths and failed trials as historical evidence. [Upload candidate](https://github.com/VOLPAROSSA/volparossa/pull/279) · [Resident model evidence](#protected-compute-evidence) · [October checkout index](https://github.com/VOLPAROSSA/volparossa/blob/425b888963243259bc269f8c8d30513660df3095/docs/IMPLEMENTATION_STATUS.md#retained-branches-and-resumption-dependencies)

## Network baseline and remaining proof

The original [full v1 checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
passes A01–A15 on `482e33d0` with complete privacy captures, real MPTCP aggregation,
path-loss survival, 25 forced crashes/helper restart recovery and zero owned
objects after cleanup. Run 34047766913 and Quality 34047735082 bind that source.
The same-build mixed-link run 34047765944 fails its WAN-only warm-route baseline
with `INGRESS_MPQUIC_DATAGRAM_REJECTED`; it proves no new LAN+WAN gain ratio.
Reciprocal owner-priority download trial 34142685975 at `efc35ac9` passes its one
configured IPv4 bottleneck; arbitrary ISP/Wi-Fi/physical-radio guarantees do not
follow. Local-only configuration alone does not prove offline private-endpoint
routing. All newer shared-service, application and update requirements remain
part of completion.

The full Core candidate at `43b71ac3` produced two identical release packages
on the Ubuntu runner, SHA-256 `0973864d3fdf348fe31f932921400e219aeebba5f85ab17488a44f95379e1d19`.
In Debian 13, the suite no longer indexed the pinned Unbound packages and the
private DNS companion was unavailable to apt. The independent network trial
passed A01–A13 and A15. A14 counted eleven remaining runtime sockets after
the forced crash. The outer host snapshots matched. The acceptance gate
withheld the downloadable package.
[Original run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44447116925) ·
[Guest package error](development/evidence/alpha-package-44447116925/package-apt.stderr)

On 19 November 2026, Core `9072cce87c77ea8e421b1261cb5e5ade80e758a7` passed
all 15 v1 cases in the twelve-node Debian 13 KVM topology. After the forced
crashes, the guest counted zero remaining owned objects and the before/after
host snapshots matched. The `alpha` workflow built the Core package twice on
one Ubuntu runner and obtained identical bytes. In Debian 13 amd64, the package
trial installed Core 0.1.0 with its matching private DNS worker, started both
Core services, ran `doctor` before and after upgrading, and removed Core. The
upgrade preserved the identity and restarted the active services. Removal
preserved the identity and configuration. The network snapshots matched.
[Acceptance report and original case evidence](development/evidence/alpha-package-44453914133/acceptance-report.json) ·
[Package lifecycle](development/evidence/alpha-package-44453914133/package-lifecycle.json) ·
[Workflow run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44453914133)

The installable QA candidate has a GitHub Actions expiry date of 26 November 2026.
The ZIP SHA-256 is `573554dd00c7b946bfd030524293fc1e9615db177047771f25d7647a32d1892d`.
The repository retains both package checksums and the original acceptance evidence.
[Candidate package pair](https://github.com/VOLPAROSSA/volparossa/actions/runs/44453914133/artifacts/14499490074) ·
[Core checksum](development/evidence/alpha-package-44453914133/volparossa_0.1.0_amd64.deb.sha256) ·
[Worker checksum](development/evidence/alpha-package-44453914133/volparossa-private-dns-worker_0.1.0_amd64.deb.sha256) ·
[Installation instructions](../packaging/README.md)

On 19 November 2026, two independent hosted runners each built the Debian
amd64 packages twice from Core `428e28999768f274e61c0267e34db4f671677b2f`.
The Core package (26,104,956 bytes) and private DNS worker (52,796 bytes)
each matched byte for byte across the two downloads. The package builder now
calculates Installed-Size from logical file sizes, so filesystem block allocation
does not change the binary archive. Both Debian 13 KVM runs passed A01–A15,
installed the package pair, preserved the identity across the upgrade and
removed the package. Each guest counted zero remaining test objects and its
before/after host snapshots matched.
[First acceptance](development/evidence/alpha-package-44530318378/acceptance-report.json) ·
[Second acceptance](development/evidence/alpha-package-44530323130/acceptance-report.json) ·
[First package lifecycle](development/evidence/alpha-package-44530318378/package-lifecycle.json) ·
[Second package lifecycle](development/evidence/alpha-package-44530323130/package-lifecycle.json) ·
[Core SHA-256](development/evidence/alpha-package-44530323130/volparossa_0.1.0_amd64.deb.sha256) ·
[Worker SHA-256](development/evidence/alpha-package-44530323130/volparossa-private-dns-worker_0.1.0_amd64.deb.sha256) ·
[First run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530318378) ·
[Second run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530323130) ·
[Download the tested packages](https://github.com/VOLPAROSSA/volparossa/actions/runs/44530323130/artifacts/14537641263)

## Fixed alpha v1 scorecard

The frozen original twenty-row, 100-point criteria and AV1/A01–A15 definitions
remain in the [preserved scorecard](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#fixed-alpha-v1-scorecard).
Its pre-vertical 11/100 value is historical, not today's score. Later accepted
same-build v1 execution is recorded above; no new full-goal percentage is assigned
by reorganizing documentation. Functional extensions remain required regardless
of that baseline milestone.

## Historical evidence index

The following anchors preserve existing incoming references while directing
historical claims to their original source-bound records. They are navigation,
not additional startup reading or current completion assertions.

<a id="current-live-integration-checkpoint"></a>
<a id="current-candidate-functional-integration-in-progress"></a>
<a id="latest-completed-integration-evidence--15-october"></a>
<a id="latest-completed-integration-evidence--1516-october"></a>

- [Original live network checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
  and [earlier functional candidate](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-candidate-functional-integration-in-progress).
- [Earlier native/consumer milestones](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence).

<a id="latest-dns-integration-checkpoint"></a>
<a id="latest-known-contact-mailbox-integration-checkpoint"></a>
<a id="latest-content-integration-checkpoint"></a>
<a id="earlier-milestone-evidence"></a>

- [DNS](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-dns-integration-checkpoint),
  [known-contact mailbox](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-known-contact-mailbox-integration-checkpoint),
  [content](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-content-integration-checkpoint)
  and [earlier milestones](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#earlier-milestone-evidence).

<a id="additional-application-and-autonomous-maintenance-scope"></a>
<a id="android-to-core-integration-boundary"></a>
<a id="warm-mpquic-growth-integration"></a>

- [Application/maintenance integration](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#additional-application-and-autonomous-maintenance-scope)
  and [Android integration evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#installed-android-verification).
- [Network candidate and growth evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-candidate-functional-integration-in-progress).

<a id="explicit-local-policy-for-protected-compute"></a>
<a id="guest-owned-protected-compute-session-candidate"></a>
<a id="protected-compute-verifier-preparation"></a>
<a id="authorized-quote-exchange-candidate"></a>
<a id="explicit-public-code-proposals-bounded-peer-repair-passes"></a>

- [Protected local policy](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#explicit-local-policy-for-protected-compute),
  [guest-owned session](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#guest-owned-protected-compute-session-candidate),
  [verifier preparation](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation),
  [authorized quote exchange](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#authorized-quote-exchange-and-authenticated-refusal)
  and [public peer repair](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#explicit-public-code-proposals-bounded-peer-repair-passes).

## Definition of done

Completion requires the full [goal and all amendments](development/GOAL.md),
including complete DPS and Studio criteria, to work through their actual
production consumers with required trust, privacy, recovery, authority and
platform boundaries. Checked work needs passing scope-appropriate evidence;
unimplemented, skipped or simulated behavior remains open. A source test,
component fixture or older passing source cannot stand in for another source's
runtime acceptance. Keep this index current with the next action and evidence
link; add detailed immutable receipts to the historical/topic record rather
than growing another session transcript here.
