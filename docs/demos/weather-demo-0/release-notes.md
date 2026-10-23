# VOLPAROSSA Weather Demo 0 — prerelease materials

Proposed prerelease: **weather-demo-0.1.0**. These are review materials;
publication is not authorized and no GitHub release has been published.

An installed Overmorrow Android application consumes real ECMWF IFS weather and
NOAA GEFS-Aerosols particulate forecasts through shared VOLPAROSSA Core and
cooperating peers. **Core runs externally to the Android emulator**, in the
isolated Debian 13 test topology. This first milestone is a reproducible developer
demonstration. It is not a supported installable technical preview or standalone
mobile application release.

The actual runtime is Core `6bc0abdb524b79e5244f9381d2d8d45a9100b41d` and Weather
`85e9eda9bb6105866db2510758e76c9930fdde91`, recorded in
[run 39998753810, attempt 1](https://github.com/VOLPAROSSA/volparossa/actions/runs/39998753810).
Its unchanged product, installed-app, independent peer/cache and cleanup checks
passed. Its additional media-duration gate failed, and the original run remains
failed. The new [scoped media admission](media-admission.md) separately verifies
the unchanged clip, native timing and committed visual witnesses; it does not
rewrite that result or claim a new runtime execution.

Final media admission/export: [40017379373](https://github.com/VOLPAROSSA/volparossa/actions/runs/40017379373),
verifier/presentation source `5c7c5470cef31c37d0cb4f961f221529bda080fb`.
Video: 119.966667 seconds, 1920x1080 H.264, with no narration audio.
Independent review inspected the actual 90-second layout, captions, source
witnesses and hash bindings; full encoded playback remains for user review.

## Evidence and assets

The review-ready bundle's `release-manifest.json` identifies the final verifier
run/source, runtime sources, original failure, input provenance, timing report,
scoped admission, visual witnesses and every file hash. `SHA256SUMS` supports
local integrity checks. The package contains:

- Approximately two-minute `weather-demo-0.mp4`; full genuine source clip at
  normal speed, followed by a visibly labelled hold of authenticated frame 206.
- Original unchanged `screen.mp4` and real temperature, PM2.5, refresh, HOME and
  return screenshots; preview PNG from the actual edited video.
- Accessible `captions.vtt` and `transcript.txt`; no synthetic narration audio.
- Original same-run delivery/cleanup reports and failed media gate, the separate
  new technical/visual admission and exact provenance.
- Exact committed runtime Core/Weather sources, final verifier/presentation
  sources, native-builder source recipes and original notices.
- Reproduction instructions and model/CI measurement with explicit uncertainty.

The completed-run reports establish 12,332 cold peer bytes for weather and 8,774
for particulate, followed by two cache-backed refreshes per product with zero
additional peer bytes. Origin body/range fallback is absent during measured peer
retrieval. Source acquisition from agencies happens separately. The closed chain
joins publication receipts, HTTP content and actual mounted app rows; pictures
alone do not prove network behavior or cleanup.

## Visible scope and limitations

The recording shows temperature and PM2.5 forecasts, model/source/validity,
actual refresh, first-refresh completion, HOME and the same application's return
animation. Wind, precipitation and PM10 columns are outside the reviewed viewport.
A settled post-resume frame and a visibly completed second refresh are not shown;
the original acceptance verifies two cache-backed refreshes and background/resume.
The original capture duration is not asserted to cover all host-side driver work.

No standalone mobile Core, physical-phone/iOS acceptance, production authority,
complete Weather service, guaranteed forecast accuracy, proven real expired-product
recovery or concurrent bulk multipath is claimed. Products are forecasts, not
current observations or a complete AQI. Publisher authentication is not ECMWF or
NOAA endorsement. Cache refresh can reuse the same still-valid publication.

No APK, SDK, native toolchain binary, private key, packet capture, private runtime
log or emulator userdata is included. Debug APKs used in disposable tests are not
supported end-user distributions. Source recipes need network access and pinned
upstream availability; this is not a self-contained offline build kit. Original
native Actions inputs expire on 26 October 2026; their digests and builder sources
are retained, but a replacement requires renewed source/ABI admission.

The full agreed VOLPAROSSA goal and active development remain unchanged. These
historical-baseline demo commits must not be merged wholesale into current main.
