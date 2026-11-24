# Application and shared-service trial records

For the current checkpoints and open work, see the [implementation status](../IMPLEMENTATION_STATUS.md).

## Development branches — 18 November 2026

The central build follows the [owner’s development mandate](../development/GOAL.md#autonoom-onderhoud-en-updates).
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
  · [Original Core, browser and cleanup receipt](../development/evidence/cloud-owner-resume-44416913278/cloud-private-upload-smoke.json)
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
  · [Application receipt](../development/evidence/immich-peer-44411540175/immich-restore-result.json)
  · [Storage receipt](../development/evidence/immich-peer-44411540175/image-topology-receipt.json)
  A separate trial on the main-based Core `b3496f1b` and Image `fdbe8187`
  repeated both peer restores and the fresh database, album and media recovery.
  Both receipts bind the same new 51,283-byte ciphertext. The owner recovered
  the original 8,516-byte picture and anonymous access was denied. All eight
  copies were deleted and all three stores returned to zero. A preceding
  attempt stopped while acquiring the pinned release, before it started Immich.
  [Main-based trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44418787447)
  · [Application receipt](../development/evidence/immich-peer-44418787447/immich-restore-result.json)
  · [Storage receipt](../development/evidence/immich-peer-44418787447/image-topology-receipt.json)
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
  [Weather run](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44427401562) · [Original expiry receipt](../development/evidence/weather-cache-expiry-44427401562/result.json)
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
  [Four-validator run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44426288636) · [Original build, consensus and cleanup receipts](../development/evidence/bank-validators-44426288636)

### Bank owner cancellation

Core `3fb7e249` installed the Bank TEST authorizer from `a65eb8a3` for its
four-validator Debian 13 trial. The owner committed 70 of 100 TEST units and
reserved another 10. The signed cancellation released those 10 to the payer.
After the signing seed was removed and one validator restarted, the reopened
reservation, payment and cancellation ran again in block 25. All four stores
agreed at height 26. The balances remained 30 and 70 and the cancellation
kept receipt sequence 4.
[Validator receipt](../development/evidence/bank-validators-44564082860/attempt-2/transaction-abci-inner.json) · [Passing run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44564082860/attempts/2)

The first attempt failed the outer host check when finite IPv6 lifetimes
increased. The second attempt used the same source and guard. It observed
normal lifetime countdown, removed the private keys and owned namespaces,
and passed. Independent light-client finality remains open.
[First host receipt](../development/evidence/bank-validators-44564082860/attempt-1/transaction-abci-acceptance.json) · [First run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44564082860/attempts/1) · [Passing host receipt](../development/evidence/bank-validators-44564082860/attempt-2/transaction-abci-acceptance.json)

## Native Firefox ordinary tabs

Core `50b92f8a` compiled Firefox 157.0.1 offline with Browser `c3311ebe`.
Both ordinary tabs verified the same 32 MiB body over two carrying MPTCP
subflows on distinct WireGuard paths. Releasing the first route at both ends
left the second transfer active. The origin observed the Exit address with no
proxy credentials. Firefox exited, its private profile was removed, the guest
network state matched and zero owned objects remained. Grant assignment in
this run used the privileged test driver. The preceding attempt stopped after
the first complete body.
[Passing build and KVM](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054)
· [Both trials and original receipts](../applications/BROWSER_NETWORK.md#two-complete-native-firefox-navigations)

## Core project website — 2026-10-30

The bounded Golden Harbour introduction lives in `website/`, with an isolated
Python static build and project Pages artifact for `/volparossa/`. It imports
reviewed shared theme v1.0.3 from homepage commit `8114d966f3e9` and preserves
development/permission boundaries from Core source `edf569300acb`.
[Website verification](../../website/VERIFICATION.md) records responsive Chromium/
Firefox renders, accessibility, no-JavaScript behavior and performance results.
This work changes no runtime or project goal and supplies no new Core, DPS,
network, model or sensor acceptance evidence. Publication follows the existing
required PR gate and the separate scoped website deployment workflow.
The owner’s subsequent visual refinement restores the four concept scenes below
the unchanged hero and adds an accessible rotating nine-application strip,
excluding Bank/Citizen; [bounded website evidence](../../website/REFINEMENT-VERIFICATION.md)
records the responsive renders, original icons and interaction checks.
The final [Compute/satellite icon correction](../../website/ICON-VERIFICATION.md)
replaces malformed custom geometry while preserving the page composition.

## Development workflow — 2026-10-26

The remaining authored documentation has been reviewed across architecture,
network, services, development, privacy, applications and component references.
Repeated checklists and superseded trial narratives are consolidated; current
wire versions and runtime/installed-package claims are corrected against source
and existing evidence. Detailed records remain in the [documentation archive](../archive/README.md).
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

## Protected Compute evidence

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
[Protected-quote run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44425796022) · [Original route and VM receipts](../development/evidence/protected-quote-44425796022)

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
[Workflow](../../.github/workflows/protected-resident-model.yml) · [Source checks](https://github.com/VOLPAROSSA/volparossa/actions/runs/42141349016) · [Prior evidence](https://github.com/VOLPAROSSA/volparossa/blob/f355776a9191ce5ade255cc299b765229e9f5e99/docs/IMPLEMENTATION_STATUS.md#protected-compute-evidence)

## Studio and shared hosting evidence

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
and the [PR343 supplement](../archive/integration-evidence-pr343-20261023.patch.txt)
retain artifacts, hashes and exact source/tree bindings without becoming routine
startup context.

## Decentralized positioning system — 2026-10-21

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
and the [service contract](../services/DPS.md) retain research and acceptance detail.

## Map, Weather and application evidence

On Core `8ca8522c` and Map `f965604d`, an independent provider delivered all 325 signed bytes to the Linux Map adapter. After disconnect, the owner reopened the same bytes with zero peer traffic. One second after signed expiry, the adapter refused a new handoff. The host snapshots matched. The road graph in this trial was synthetic. In a separate Android 35 emulator, two cold launches of the original Organic Maps app calculated walking routes of 390 m and 490 m using the Monaco map package in airplane mode. The subsequent desktop trial used a separately seeded signed feed on the real Monaco graph. The joined mobile path remains open. [Peer traffic trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44438057954) · [Organic Maps trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44444481182)

Two cold Drizz.li builds produced identical bytes for all 97 tracked files. In the browser trial, the expired ECMWF publication returned HTTP 503. Drizz.li then displayed 9 °C from signed revision 2. Overmorrow passed all 24 Flutter tests in three independent release builds. All 64 output files matched in relative path, mode and content, totalling 24,608,666 bytes. Physical devices and iOS remain open. [Drizz.li build comparison](https://github.com/VOLPAROSSA/volparossa-weather/pull/41) · [Forecast refresh](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44445914018) · [Overmorrow comparison](https://github.com/VOLPAROSSA/volparossa-weather/pull/44) · [Third build](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44447940253)

The original Silex dashboard ran in Chrome against its Rust server. The operator created, renamed and duplicated a project. After restarting the server and browser, the dashboard listed both projects and the operator deleted them. A separate build produced the native 34,281,248-byte Silex executable. Native WebView execution and publication authorization remain open. [Dashboard trial](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44445227423) · [Native build](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44444745137)

Signal Desktop processed delivery receipts for two simulated encrypted peers. After reopening its SQLCipher database, three intended receipts still showed delivered, the cross-recipient control still showed sent, and the four message IDs matched. In a separate Citizen trial, the upstream Belenios verifier and public replay checked the encrypted ballots, decryption and totals for three fictional referenda. Four yes votes among six eligible residents adopted the proposal, four no votes rejected it, and three yes with one abstention left it undecided. [Native Signal run](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44435698764) · [Offline Belenios run](https://github.com/VOLPAROSSA/volparossa-citizen/actions/runs/44434956603)

Signal Desktop exported a 198,352-byte encrypted backup. When two of three Storage providers went offline, two of four fragments remained readable and the owner received no partial output. After one provider returned, the owner recovered all four fragments and imported the original backup in Signal. All three providers reported zero remaining usage after cleanup. [Native Signal and Storage trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44444982433)

With Thunderbird closed, the owner’s Stalwart server accepted a second message over local SMTP. It rejected an unknown local recipient and external forwarding. After Stalwart restarted on the same SQLite database, the owner recovered both the original import and the delivered message, including its stored transport headers. This exercised an isolated loopback mail server. [Source-bound Thunderbird and Stalwart receipts](https://github.com/VOLPAROSSA/volparossa-mail/tree/5bb90ec3be8c168fd58a19e2d03f626f6560d96b/third_party/thunderbird-stalwart-owner-smtp)

## Paired Mail delivery

On Core `d272a11b` and Mail `30cc423a`, the sender and recipient used separate Core agents, control sockets and network namespaces. While the recipient was offline, both custodians accepted 91,992 encrypted bytes. With the sender offline and one custodian restarted, Stalwart imported all 90,139 original MIME bytes. Both custodians signed the acknowledgements after import. The next fetch returned zero messages. Enrollment, send and receive completed 2, 2 and 7 Exit MPTCP/TLS exchanges respectively. All nine captures recorded zero direct client–Exit packets and zero packet-socket drops. Cleanup left zero owned objects and the host snapshots matched. The fixture kept both clients isolated from direct Exit routes. [Original guest report](../development/evidence/paired-mail-peers-45424248328/paired-mail-peers-smoke.json) · [Hosted topology trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45424248328)

The 36-file ZIP measured 35,643 bytes with SHA-256 `0352630c680dd0ae2482bb074d2207b6fc8a8b8db86bfc89c832b008c196ee4c`. Its original 143,213-byte guest report has SHA-256 `986038d2481659d78a781fa4e73fb88bb0109439e6983cab92412107e22181ac`. The preceding guest on `ec90f352` also completed delivery, but its 143,265-byte report exceeded the original 131,072-byte export limit. [Original ZIP](https://github.com/VOLPAROSSA/volparossa/actions/runs/45424248328/artifacts/14937032554) · [Earlier export failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/45417945039)

On Core `b9c01e97` and Mail `30cc423a`, the paired sender and receiver used separate application processes behind one Core client. Two providers confirmed custody of the encrypted message. After the sender profile was removed and one provider reopened its store, the owner retrieved the message over a fresh protected route. Stalwart returned all 90,139 original MIME bytes before either provider acknowledged import. The next fetch was empty. The sender and receiver phases recorded six and seven Exit MPTCP flows respectively. The guest host snapshots matched and cleanup left zero owned objects. [Protected route and application receipt](../development/evidence/paired-mail-44553382181/paired-mail-smoke.json) · [Hosted topology trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44553382181)

In the earlier local-provider trial on Mail `30cc423a`, Stalwart restarted after losing its import reply. The retry recovered the same 429-byte message, and a fresh Thunderbird profile opened it over implicit TLS. On Mail `94f3162d`, the sending Thunderbird profile submitted both a saved draft and a newly composed message. The recipient opened them in its Inbox. Automatic pickup later delivered a third message after reconnection. [Original import and recovery receipt](../development/evidence/mail-owner-44547309790/peer-mail.json) · [Sender and receiver trial](https://github.com/VOLPAROSSA/volparossa-mail/actions/runs/44562762968)

## Latest completed integration evidence

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
