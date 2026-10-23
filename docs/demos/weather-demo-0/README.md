# VOLPAROSSA Weather Demo 0

An installed Overmorrow Android application retrieves real forecast products
through VOLPAROSSA Core and cooperating peers. **Core runs outside the Android
emulator, in the disposable Debian 13 topology.** This is a developer demonstration,
not a standalone mobile release or a production VPN distribution.

The full [VOLPAROSSA goal](https://github.com/VOLPAROSSA/volparossa/blob/main/docs/development/GOAL.md),
including DPS and Studio, remains unchanged. These historical-baseline demo branches
must not be merged wholesale into current main: current Storage, Compute, DPS,
Studio, helper and application work remains independently owned.

## What is being reproduced

Original successful [run 38717988016](https://github.com/VOLPAROSSA/volparossa/actions/runs/38717988016):

| Input | Original revision |
| --- | --- |
| Core | `aac5be7f602fae9754153cdcb5c401ecb9ee7cb6` |
| Weather | `3b90442a9d5be4db73ccf83cba2028364980c3ca` |
| Overmorrow | `97995e2e00e454389e00e35f1e65654afe3e8bed` |
| Flutter | 3.38.5, `f6ff1529fd6d8af5f706051d9251ac9231c83407` |

The recording extension is a separately recorded derivative of these sources.
It does not replace the original result. New live acquisitions necessarily have
different runs, validity windows, bytes and hashes; historical byte counts are
never used as the expected current forecast. The v6 product contracts, explicit
publisher authority, receipt/HTTP/app-table joins and cleanup remain required.

The original run proved cold peer delivery, two cache-backed refreshes per
product, actual Android taps and background/resume. It did **not** establish
visible pixels, real-product expiry recovery, physical-device/iOS support,
concurrent bulk use of multiple subflows, forecast accuracy or production authority.
New media must be bound to the new run's own final acceptance. The separate
[scoped media contract](media-admission.md) preserves the failed original workflow
conclusion while checking coherent source media and explicitly reviewed scenes.


## Recorded result and review package

[Final media run 40017379373](https://github.com/VOLPAROSSA/volparossa/actions/runs/40017379373)
succeeded on verifier/presentation source `5c7c5470cef31c37d0cb4f961f221529bda080fb`.
The `demo/weather-0-video-20261023` branch is frozen at this revision. The separate
release-draft branch adds final documentation/evidence without changing executable
sources. The video is 119.966667 seconds, H.264, 1920x1080; SHA-256
`e4f72aa6d8236c56ef9d638d5f40563d7865b5411b6d3e7510dd43cee42c4d40`.
See the [exact new records](trials/40017379373/) and
[independent final review](trials/40017379373/final-presentation-review.json).

The complete CI evidence ZIP has 546 verified files and remains a separate release
asset; the source/review bundle includes selected screenshots and closed records.
Inspection-record paths describe that original ZIP, not a promise that every one
of its 490 PNG frames is duplicated in the smaller bundle. `SHA256SUMS` describes
exactly the files included in the bundle. Load `captions.vtt` alongside the video;
the video has explanatory text and no narration audio. Full encoded playback
remains for user review. Forecast freshness is historical at the original capture,
not a current-weather claim when replayed later.

## Reproduce on a disposable hosted runner

Requirements: repository Actions execution rights, the exact pushed demo source,
public availability of the pinned upstream archives, and an ordinary GitHub-hosted
Ubuntu 24.04 runner with KVM, sufficient RAM and at least 32 GiB free space.
The demonstrated platform is Debian 13 amd64 with the Linux x86-64 Android
API 36 emulator and an installed debug application. Physical Android/ARM and iOS
are unaccepted. Exact SDK, Flutter, decoder and upstream inputs are retained in
the source archives and Weather's
[pinned input manifest](https://github.com/VOLPAROSSA/volparossa-weather/blob/85e9eda9bb6105866db2510758e76c9930fdde91/third_party/hosted-runtime-inputs.json).
The existing workflow owns its Debian guest, emulator, temporary AppArmor policy,
temporary runner-private KVM ACL and cleanup. Do not run it on a development host,
relax its resource checks, or replace KVM with unverified emulation.

1. Inspect the candidate commit and the workflow's fixed Weather revision.
   Inspect any existing run for that exact source before dispatching another.
2. Dispatch the existing workflow with recording explicitly enabled:

   ```sh
   gh workflow run weather-android-delivery.yml \
     --repo VOLPAROSSA/volparossa --ref demo/weather-0-video-20261023 \
     -f record_demo=true
   ```

3. Record the returned run ID and candidate commit. Check its existing status
   occasionally; a terminated watcher is not grounds to rerun the trial.
4. Require the unchanged original hosted application/delivery/cleanup acceptance.
   A recording alone is not a passed delivery trial. Preserve any additional
   media failure and quarantine unchanged; use the explicit scoped contract
   below only after actual frame review of that exact new recording.
5. Inspect the actual screenshots and recording. Reject blank, illegible,
   obscured or unrelated frames. Generic timed screenshots are not automatically
   initial/refresh/resume observations.
6. Review the assembled video, captions, transcript, provenance and limitations.
   Retain the original recording separately from any edited presentation.

The workflow performs network/toolchain builds only inside the approved disposable
hosted environment. It installs nothing on the contributor's workstation.
Source/data acquisition is separate from the overlay retrieval measurement.
Refresh reuses a still-valid product; it does not imply a new forecast acquisition.

The optional recorder has a 180-second ceiling and starts before the unchanged
driver. Its original duration check is retained for historical reproducibility;
it compares unlike clock/process boundaries and rejected the retained trial.
The original trial remains failed. No driver deadline, network test or cleanup
requirement is relaxed. The separately reviewed contract below requires coherent
native media and actual scene coverage instead of host-wall duration coverage.

### Reassemble and validate the retained genuine trial

The retained runtime is Core `6bc0abdb524b79e5244f9381d2d8d45a9100b41d`, Weather
`85e9eda9bb6105866db2510758e76c9930fdde91`, run `39998753810`, attempt 1.
Its delivery, exact displayed-data joins and cleanup passed. The original extra
media gate failed; see [the unchanged reports](trials/39998753810/) and
[the separate scoped admission](media-admission.md). The public Berlin fixture
uses ECMWF IFS and NOAA GEFS-Aerosols model run 23 October 2026 00:00 UTC.

Inspect the pushed branch's commit and require it to match the final verifier
revision in the release manifest before dispatching. The following command only
reviews the retained capture; it does **not** rebuild Android or rerun Core:

```sh
gh workflow run weather-android-delivery.yml \
  --repo VOLPAROSSA/volparossa --ref demo/weather-0-video-20261023 \
  -f review_run_id=39998753810 -f review_attempt=1 \
  -f review_core_revision=6bc0abdb524b79e5244f9381d2d8d45a9100b41d \
  -f review_quarantine=true -f review_native_frames=true \
  -f review_scoped_demo=true
```

Check the resulting run's `head_sha`; a mutable branch name alone is not a source
pin. The reviewer checks the original artifact's digest, unchanged report chain,
all native frame hashes/PTS, metadata-track timing and committed visual witnesses.
It creates `scoped-admission.json` and an unpublished presentation separately;
the quarantined manifest and inspection's false acceptance flags stay unchanged.

Quarantine artifact `12522458881` is 7,747,546 bytes, SHA-256
`307ebd6239de51d40b17c429658fe751b4201abcda8a0e4abd5688184121230c`.
The original clip is 3,097,781 bytes, SHA-256
`bca54a8f677238f26daff6921bb3af0c661e1b39d0aada5ce3f161fda380d5c8`.
The artifact is retained for 14 days; a later missing download is a blocker,
not permission to substitute another clip. The review-ready local bundle retains
these admitted files independently of Actions expiry. Replaying retained evidence
is distinct from a new live source-data acquisition/runtime reproduction.

The AOSP recorder implementation writes one H.264 video track and two Winscope
timing metadata tracks in MP4. This explains the observed count of three in the
pinned Android API 36 trial; the actual type/tag profile still requires admission.
These timing tracks are not additional pictures or audio. The
format-specific validator checks the expected track tags and still rejects other
streams; the edited presentation selects video only. The source behavior is
documented in [AOSP screenrecord](https://android.googlesource.com/platform/frameworks/av/+/297eaacfa6/cmds/screenrecord/screenrecord.cpp).
Synthetic container probes exercise the media tools, not app or network behavior.

## Data, compatibility and retention

Weather remains IFS `0p25` temperature, wind and precipitation forecasts plus
separate NOAA GEFS-Aerosols PM2.5/PM10 forecasts for an explicit public community
area. These are forecasts, not current observations or a complete AQI service.
Missing capabilities remain unavailable and native valid times/windows remain
distinct. No private location, location search or geolocation permission is needed.

[ECMWF's current catalogue](https://www.ecmwf.int/en/forecasts/datasets/open-data)
reports field-specific GRIB packing changes from 20 October 2026 and a new 0.1-degree
product. This demo retains `0p25`; it does not silently adopt the new resolution.
Successful new native decoding and original field-identity checks, not a catalogue
claim, determine compatibility with current input bytes. Failed acquisition or
decoding must remain a failed run; do not substitute synthetic products.

The unchanged v6 input manifest identifies decoder artifact `11731895956`
(Weather run `38214736539`) and ABI artifact `11732188075` (Core run `38216142236`).
Their original archives expire on 26 October 2026. Exact digests and retained
builder-source identities are in [native-inputs.json](native-inputs.json). The original Android acceptance
artifact `11966068479` expires on 29 October. A missing archive is an explicit
reproduction blocker, not permission to repin an arbitrary binary. Use reviewed
source builds and a newly recorded admission if inputs must be renewed.

## Acceptance and publication

- Original guards, negative controls, source verification and deadlines remain in force.
- Real peer retrieval, authenticated publication content, no unclaimed origin
  fallback, warm-cache reuse and exact app-table correspondence must pass.
- The actual emulator pixels and interactions must be recorded within that run.
- App/forward/process/VM/policy cleanup and exact KVM ACL restoration must pass.
- Sources, dependencies, original reports, media hashes and edits must be inspectable.
- The external-Core boundary remains visible throughout the presentation.
- No APK, SDK, emulator userdata, private keys, packet captures or private logs enter
  the public presentation bundle.

The proposed prerelease is `weather-demo-0.1.0`. Prepare materials locally and as
scoped Actions evidence and, once reviewed, an **unpublished GitHub draft**.
Do not publish the release, make release assets public or communicate results
externally without the user's explicit publication approval. Include installable binaries only after their exact
installation/runtime acceptance, outside this source-and-evidence demo scope.

See [release notes](release-notes.md), [storyboard](storyboard.md), and
[licenses and attribution](NOTICES.md). The release draft identifies the exact recorded evidence and remaining publication gate.
