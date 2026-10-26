# Decentralized Positioning System

DPS is a shared VOLPAROSSA core service for local positioning, source consistency
and eventually independent GNSS integrity assessment. It uses the existing five
DICN infrastructure layers. The [DPS section of the complete goal](../development/GOAL.md#dps)
defines its functional requirements. This page records service design and staged
acceptance, without capping that scope. The [source archive](../archive/requirements-20261023/README.md)
retains the received texts and hashes. The [implementation ledger](../IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21)
records accepted evidence. Chat attachments or transcript context are not
requirements dependencies. This design is not a claim of working sensor fusion,
GNSS-free navigation, anonymous ranging or comprehensive spoofing detection.

## Shared service and device boundary

Keep platform sensor adapters separate from the common assessment and estimation
logic. An adapter must obtain the relevant application/OS permissions, validate
device capabilities and calibration, and attach measurement time, reference frame,
units, provenance and uncertainty semantics. Receiving help, measuring locally,
contributing measurements, storing history and training shared models are separate
permissions. Overlay participation grants none of them.

The first executable slice is a stateless `DpsAssess` operation on the existing
bounded local-control service, with its own DPS schema version. A caller explicitly
supplies observations it already holds. The operation acquires no sensors, starts
no radio scans, retains no location history and publishes no data. Its existing
Unix socket authorizes local administrative callers; it is not yet a per-app
least-authority location broker. Untrusted mobile apps must not receive that
administrative socket as a shortcut to location access.

A bounded hosted runtime proof now exercises one normal launch of the dormant
daemon, framed status and a synthetic DPS request, joined shutdown, and removal
of its owned socket and fixture. Quality `39630688730` and CodeQL `39630681739`
pass on PR305 source `350a013de73334b2deb18843057cb964101989d7`; the temporary PR test
merge against main has an identical tree to that source. The closed receipt reports only synthetic
DPS activity and unchanged bounded host observations. This does not grant apps
location access or establish app-owned permissions, active-participation
behavior, restart/crash recovery, complete namespace cleanup, sensor acquisition,
fusion or physical accuracy. The administrative socket remains unsuitable for
untrusted apps.

The local-control envelope remains version 2; DPS schema version 1 uses request
field 64 and response field 64. Allocation was checked against main and all 23
open PR heads on 2026-10-21. The retained Storage integration already uses request
fields 46–49 and response fields 34–37; historical draft assignments also remain
reserved until their integration/migration is resolved. The unreleased DPS
prototype's conflicting request 46/response 34 are superseded without aliases.
Checking main alone is insufficient when allocating fields across retained work.
Golden wire fixtures bind both DPS envelope fields to 64.

Version 1 compares declared three-dimensional positions in metres: WGS84
Earth-centred Earth-fixed coordinates or a named local Cartesian frame. WGS84
is a caller assertion, not verified geography. Local coordinates do not imply a
geographic anchor. Geodetic conversion, vertical datum conversion and anchor
validation belong to subsequent explicitly tested adapters. Never compare
unrelated local origins, epochs or altitude datums as one frame.

The request selects a frame and carries a bounded batch (at most 32 observations),
opaque request-local source/correlation identifiers, reported age, source kind,
position, uncertainty radius and navigation-message authentication metadata.
No permanent node identity, public IP, radio address or human-readable device
path belongs in that contract. The actual request/response fields and enum values
are defined in `crates/volparossa-local-control/src/dps.rs`.

Assessment validates sizes, versions, enums, finite values and coordinate/radius
bounds. It excludes stale, invalid and incomparable observations with explicit
reasons. It compares every valid comparable pair, including members of the same
declared correlation group. A disagreement cannot be hidden by copying a report,
renaming sources or claiming that its navigation message was authenticated.

The output distinguishes unavailable, single-claim, consistent-claims and
conflict outcomes. Where a candidate is returned, it is an explicitly unverified
input position, not an average or newly computed position. A conflict withholds
that candidate; no majority silently replaces suspected GNSS. The supplied radius
is a consistency threshold with unknown confidence, not a calibrated protection
level. Freshness and provenance remain caller-supplied claims. Different group
labels do not prove physical independence, and agreeing inputs do not establish
truth. This first slice makes those limitations machine-readable; it does not
implement the subsequent positioning estimator.

Measurements are not propagated to a common epoch or compensated for motion in
this slice. Two genuine fixes at different times can therefore conflict during
movement. A conflict is an input-comparison result, never an attack diagnosis;
time alignment and motion models remain part of the required estimator work.

The development example uses two synthetic position claims. In an approved
disposable build environment, run
`cargo run --locked -p volparossa-local-control --example dps_assess` for the
in-process assessment. Passing an already-authorized agent Unix-socket path after
`--` sends the same synthetic claims as one actual framed request, with a five-second
deadline. Output contains quality/limitations only. The example acquires no real
position; the administrative socket is not a mobile-app permission mechanism.

### Next native Map adapter

The first Android consumer will reuse `DpsAssessRequest::assess` through an
app-owned, separately typed native bridge. Keep the shared assessment in Rust;
isolate any required JNI/FFI unsafe boundary from the existing safe core. This
does not require giving a mobile app access to the administrative control socket.
The app remains responsible for its OS permissions and its own consent scope;
an in-process consent object is not proof of cross-process app identity.

The pinned Map
[adapter plan](https://github.com/VOLPAROSSA/volparossa-map/blob/0bb33832f3c557c6db63e89f7a4f668cd9dceb30/docs/DPS_INTEGRATION.md#next-app-owned-android-slice)
identifies the actual Organic Maps SDK/JNI/CMake seams. Its existing location
listener can immediately replay a saved real fix, and starting its location
helper can start sensors. A synthetic-only native quality fixture must therefore
use a separate coordinator and stay outside both that helper and the GPS/track
forwarding path. No Rust linkage or DPS coordinator exists in the pinned native
app yet; the Python component is not an Android bridge.

### Quality-only native ABI

#### Historical Map checkpoint

This is the dated checkpoint recorded when PR10 was at source
[`3abb91fa`](https://github.com/VOLPAROSSA/volparossa-map/tree/3abb91fa56a5bdf1b27337c689a409986caed793).
It passed source gate `39664119379` with 13 inert tests. Actual hosted trial
`39664284521` failed its pre-existing KVM-access requirement before acquisition or
native execution. This historical result is superseded as the current source
checkpoint below; the failure remains part of the evidence record.

#### Current Map checkpoint — 2026-10-22

The current actual PR10 trial uses source
[`f3296c21`](https://github.com/VOLPAROSSA/volparossa-map/commit/f3296c21f9787cb760e561954652158c7b21601d),
tree `0002fa35860355a41541aa4563870909b03e7a5e`. Source gate `39694301016`
passes 93 inert checks and Components `39694300657` passes 31. Actual run
`39694570310` passes all eight Android/JNI instrumentation cases, including the
real Rust/JNI golden and permission-boundary test; private process-group and
cleanup controls also pass. The full fixture fails `KVM_DEVICE_CHANGED`, with
only `ctime_ns` and `mtime_ns` changed. This does not identify whether udev,
another process or the trial caused the metadata change. No normalization or
waiver of this baseline failure is accepted.

The preserved artifact `12390187577` is 97,745 bytes with SHA-256
`e8a5320620919713895a5435e12826254719cb099cbe664fbb017459e1d0ac0e`.
The instrumentation receipt is 5,558 bytes, SHA-256
`f577b7780b302c55f93888d2ec617ea749f39b8a5e18e3108fca24a0d095e2e3`.
The trial has no sensor exercise, physical accuracy, confidential execution or
main Map navigation. Earlier actual trial `39690910102` on source
`b64fba86d56ef1ac9e8d1afe89274c009bb7fffe` remains failed at its eighth test
after seven passes; its KVM timestamp difference also left the host baseline
unconfirmed. That earlier failure does not explain the current trial.

A separate four-path KVM diagnostic candidate contains one query-only negative
control followed by one empty-VM control. Its 112 total inert checks include 19
new checks; independent Sol review passes all 20 focused checks. It is published
as Map PR11, head
[`f23d8a8b`](https://github.com/VOLPAROSSA/volparossa-map/commit/f23d8a8b31633bb62bc3f0581b6332d5273ff880),
tree `a941a3c057caee886ca3bd6599fc24f803162b6e`, directly based on PR10
source `f3296c21`. Source run `39696441858` passes 112 inert checks and Components
`39696441713` passes 31. Actual control `39696546767` completes the bounded
experiment: the original API12 query/close preserves all metadata after 250ms;
one empty type-0 VM create/close then changes only ctime/mtime. VM/system
descriptors close, the namespace group drains within its unchanged 10-second
budget, and outer groups/state clean up. No SDK acquisition or Android execution
occurs. The strict phase and overall host-baseline checks still fail. Artifact
`12391605549` is 5,724 bytes, API/ZIP SHA-256
`d7c6dee986c0673f8531bd353d33e08a4437913356c9211c12ccb8f8a331581a`;
its committed source/pins and run/attempt match. This reproduction does not
identify the timestamp actor, exclude delayed/transient changes, explain past
runs or authorize normalization. Keep this diagnostic separate; do not merge it
into PR10 or main as the app fixture. See the
[implementation ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
for shared-core and current trial status.

#### Earlier Map checkpoint — 2026-10-21

At that snapshot PR10's published source was
[`02cf65b9`](https://github.com/VOLPAROSSA/volparossa-map/commit/02cf65b9cea0fd9a09e51f434d8b55deccb40fb7),
tree `5d5bbafa9a659ff81a046870b4f46af9cee3d7bd`. The independently reviewed
change enables loopback in the verified private offline-build phase and adds inert checks;
source gate `39678152908` passes 56 tests and Components `39678152985` passes 31.
Actual run `39679300414` is in progress on this exact source. Previous actual
trial `39676098216` completed public acquisition and build, then failed the
isolated offline stage at `LOCAL_ADDRESS_SELECTION`. KVM probe API 12 and the
public native build are separately evidenced; Android JNI/runtime execution is
unproved. Its process groups drained and state was removed, but the IPv6 raw
state hash differed, so the host baseline is unconfirmed. This correction does
not normalize IPv6 or establish the cause of that IPv6 discrepancy. The earlier
`3abb91fa` KVM-access failure, `4e165e6e` offline-build failure, `33c80178`
firewall raw-hash failure, `c479fbd2` unexplained baseline and earlier KVM
probe remain historical and are not generalized to the new source. No native
Android execution, sensor access, positioning or accuracy is established.
See the [implementation ledger's current snapshot](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
for shared-core and current trial status.

The shared Rust assessor has a separately testable C ABI. PR314 source
`4d4612200e0a4a46546e0c827a3f3e7f0b73c669` has accepted tree
`bac45917af63e152ddb232a885446cb7221c84bb`; that source is integrated on main
`0f15a349d3fe34131a806241c3efcb7c8a1cdb8d`, whose tree is
`985b9d834381701f19d05ae4c0a2a4e6353fe782`. Its
36-byte response is exactly nine `u32` quality/limitation fields; the canonical
bare-protobuf request is bounded to 16 KiB. The response contains no coordinates
or fix; the library acquires no sensors, keeps no history and accesses no
administrative socket. Keep the Rust assessment as the
single algorithm implementation; the Map adapter must not introduce a second
estimator or turn a relative/unavailable assessment into a GPS fix. This narrow
ABI is privacy/quality plumbing only and proves neither app identity nor location
authority, Android integration, positioning accuracy or native navigation.

Hosted run `39659133028` passed on ABI source
`aae217d3341d50ea3f925ac58059a705ba215f75`, with 12 Rust tests, 18 C11 and 18
C++17 synthetic caller cases under ASan/UBSan, and 36 separate full-library
Valgrind cases. The Rust library was not itself sanitizer-instrumented. Artifact
`12373670287` has verified API/ZIP SHA-256
`f246d0481ee3f83950134ce4da76bdb0be698529a87886873d02024f5076b0a4`.
Corrected main composition `4d4612200e0a4a46546e0c827a3f3e7f0b73c669` has
passed independent exact-scope review and the same dedicated native checks in
`39661011331`. Combined Quality `39661019902` and CodeQL `39661012097` pass;
the former records 4,244 passed workspace executions, zero failures and 12 ignores.
Current artifact
bindings and historical failures are in the implementation ledger. The
earlier combined run `39656846006` failed cargo-deny on a wildcard dependency;
the corrected exact dependency version is now in the candidate.

The separate Map candidate lives in
`.volparossa-dev/worktrees/map-native-dps-jni-20261021`, based on pinned Map
source `e8fdcca87575e238894d579797379de9c3516384`. It is a standalone,
debug/test path designed to require no permissions, with an app-owned coordinator
and C/JNI boundary;
it does not load the Organic Maps framework or request location. Link the
standalone native target to the new Rust static library and required Android
system libraries; do not route it
through Organic Maps' existing JNI helper or `JNI_OnLoad`. At the initial source
checkpoint, thirteen inert tests passed and Android had not run; subsequent
partial native evidence is recorded above. Initial independent review found a SIGTERM
cleanup bypass, background lifecycle tests that revoke/expire before entering
background, and missing deterministic coverage of expiry between posting and
display. The revised
candidate adds controls for these cases and passes independent rereview; the
implementation ledger records exact source and test boundaries. Preserve
generation-based revocation, monotonic expiry and joined cancellation; keep all
work outside the real location helper, GPS listeners and track route. The
existing JNI lifecycle does not establish OS app identity. No native Map runtime,
sensor, positioning or accuracy claim follows from source or hosted ABI checks.

Before work and again before publication, check the app-owned consent generation,
monotonic expiry and active lifecycle. Revocation, disable or backgrounding clears
selected DPS state and invalidates pending results; an obsolete completion must
not republish them. The initial Android fixture uses synthetic Cartesian data
while location permission is denied, and must prove displayed quality, expiry,
revocation during work, background/resume, late-result rejection, unavailable
offline input, no sensor/network activity and joined owned work. This establishes
only the native adapter boundary when actually exercised. Real sensor acquisition,
frame conversion, location precision authorization, independent GNSS integrity and
navigation remain required subsequent work.

## Research and implementation choices

Primary sources were consulted on 2026-10-21. The following are candidates and
constraints, not imported dependencies or tested hardware support. Before adopting
third-party code, pin the exact revision, review its licence/dependencies and tests,
and record provenance and local changes in `THIRD_PARTY_LICENSES.md`.

| Capability | Evidence and consequence for DPS |
| --- | --- |
| Linux GNSS and receiver metadata | [GPSD TPV documentation](https://gpsd.io/gpsd_json.html#_tpv) describes partial reports and warns that reported errors may have different or unspecified confidence. Use the supported client interface after explicit consent; missing position, time or uncertainty stays missing. Receiver time is not trusted host time. No GPSD instance or hardware is assumed present. |
| GNSS research and receiver testing | [GNSS-SDR](https://gnss-sdr.org/) provides an open-source receiver and testing methodology. Consider pinned, licensed sample replay for receiver evaluation separately from live hardware acceptance. Raw recordings may expose private locations and require suitable data rights. |
| Galileo authentication | [GSC OSNMA service](https://www.gsc-europa.eu/galileo/services/galileo-open-service-navigation-message-authentication-osnma) and [GSC FAQ](https://www.gsc-europa.eu/galileo/faq) distinguish authenticated navigation data from authenticated position/velocity/time. OSNMA does not prevent all spoofing or protect against jamming. Record the receiver's reported authentication status without promoting it to verified physical position. Trust material and receiver-time requirements need a real adapter and independent tests. |
| Wi-Fi ranging | [Android Wi-Fi RTT](https://developer.android.com/develop/connectivity/wifi/wifi-rtt) requires compatible device/access-point hardware, permissions and suitable foreground operation. Range is not an absolute position; anchor geometry, reference trust, multipath and measurement uncertainty matter. A MAC address must not become a persistent location identity. |
| UWB and peer ranging | [Android UWB](https://developer.android.com/develop/connectivity/uwb) requires secure out-of-band parameter exchange and describes provisioned STS plus background report restrictions. Test session termination, relay attacks and real device support. Lower-layer ranging may continue when app reports stop; cancellation is part of resource/privacy acceptance. |
| BLE | [Bluetooth Channel Sounding](https://www.bluetooth.com/learn-about-bluetooth/feature-enhancements/channel-sounding/) combines ranging techniques and distance-bounding protections. It is distinct from RSSI proximity and requires supported hardware. Neither ordinary BLE availability nor stronger signal strength proves a dependable distance. |
| Inertial, compass and barometer | Research calibrated acceleration/gyro integration and independently checked heading/pressure observations. Bias, magnetic interference, pressure variation, time synchronisation and reference drift must enter the error model. These sensors do not establish a global geographic origin on their own. Sensor access and sampling budgets remain platform-owned. |
| Visual-inertial odometry | [ETH OKVIS](https://github.com/ethz-asl/okvis) is a candidate for visual-inertial research. Camera permission, calibration, compute/energy cost, retention and the licence of the exact selected code and dependencies must be reviewed. Do not enable camera capture or network image processing implicitly. |
| Fusion and frame handling | [robot_localization's upstream overview](https://index.ros.org/p/robot_localization/) and [navigation transform documentation](https://github.com/cra-ros-pkg/robot_localization/blob/rolling-devel/doc/navsat_transform_node.rst) are references for EKF/UKF estimation and datum-aware GNSS integration. Evaluate established estimators against outliers, correlated errors and missing data; do not infer integrity from a small covariance. No ROS runtime is selected by this document. |
| Apple platforms | [Nearby Interaction](https://developer.apple.com/documentation/nearbyinteraction) is the platform investigation entry point. Its detailed documentation was not readable through this session's research tool; device/API/permission and background constraints remain unverified. No Android capability is assumed portable to iOS. |

The first algorithm intentionally only checks claimed spatial consistency. The
next estimator needs measured calibration, explicit temporal alignment and
correlation handling. Compare robust residual gating and accepted Kalman or
factor-graph methods before choosing a dependency. Keep GNSS-only, non-GNSS-only
and combined estimates distinct so a GNSS-derived anchor or prior cannot become
independent evidence against that same GNSS source. Detect time jumps using a
separate local monotonic clock; no sensor message may set the OS clock.

## Privacy and shared infrastructure

Network communication retains exactly one relay on each ordinary Internet path.
Explicit local measurement links have separate permissions and bounded lifetimes;
they do not grant direct exit access. Encrypted ranging exchanges still reveal
radio presence, timing and physical proximity. Temporary identifiers alone cannot
guarantee anonymity against observers correlating those signals.

Cache only authenticated, public, redistributable reference data with clear
validity and licence. Private coordinates, anchor addresses inside homes, camera
frames and movement history are excluded by default. Private storage/sync needs
separate consent and the uniform Storage redundancy policy. Shared compute may
process public/synthetic evaluation data; private material requires the existing
protected-execution authority and actual protected capacity. Shared AI training
requires separate permission and suitable protection. Transactions are not a
positioning dependency and must not gate access to DPS.

Future sessions need app/profile-scoped grants, expiry/revocation, minimum
precision, sampling/energy limits and cancellation, with no cross-app identifiers.
Default retention is none; diagnostics contain counts/status only. Explicit
history export must remain private. No global OS location-provider replacement
is authorized. Changes in integrity must be visible to the consuming application.

## Application integration priorities

These priorities implement the received application requirements and subsequent
continuation. They do not displace existing critical integrations.

| Application | Useful integration and boundary |
| --- | --- |
| Map / Organic Maps | First consumer: optional local DPS assessment and later a genuine alternative/hybrid location source. Preserve offline navigation and platform permissions; show stale/conflict/unavailable and relative-only states. Relative coordinates cannot be drawn as verified geographic location. Native UI/location injection and real route/navigation trials remain required. |
| Weather | Optional user-authorized local weather selection and geographic association of permitted observations. Do not double-count correlated observations, replace a chosen location, publish precise coordinates, or treat estimated weather as a position reference without evidence. |
| Image | Optional quality/provenance for user-chosen geotags. Existing images, private coordinates and inferred movements remain private; correcting metadata requires explicit scope. |
| Chat / Mail | Only explicit encrypted location sharing with the selected recipient and precision/expiry. Preserve the Signal Protocol and limited retention in Chat, including future local positioning features. Receiving DPS help does not authorize sharing. |
| Browser | Origin-scoped permission and precision controls through a future browser adapter. No background geographic fingerprint or bypass of browser geolocation consent. |
| Cloud | Optional private storage/synchronisation of explicitly retained records; no automatic location history. |
| Studio / hosted websites | The [permanent hosting addition](../development/GOAL.md#studio) permits useful optional map/location components only within explicit purpose and precision permissions. A map does not authorize publication of coordinates, movement history or private media metadata; use the existing DPS/Map and browser boundaries. |
| Code | Reuse service contracts and synthetic evaluation tools; no default need for the developer's physical location. |
| Bank / Citizen | No default positioning dependency. Location is not identity, residence, citizenship, financial authority or voting eligibility. Any concrete future use needs its own justified authorisation and threat analysis. |

## Acceptance sequence

1. Verify the bounded stateless API, strict rejection, explicit uncertainty,
   conflicting/correlated claims, version compatibility and content-free errors.
   Exercise real local-control framing and the production connection handler on a
   disposable runner. The exact-source hosted normal-daemon test also passes for
   one dormant launch, synthetic request, joined normal shutdown and owned
   socket/fixture removal; see the implementation ledger for run and receipt
   hashes. This bounded proof does not establish complete daemon lifecycle or
   app-facing location authority.
2. Join Map through a bounded app-owned adapter and demonstrate displayed quality,
   consent revocation, expiry and safe unavailability with synthetic fixtures.
   Label this as adapter evidence, not native sensor/navigation acceptance.
3. Integrate permitted Linux and mobile sensor adapters with independently captured
   reference data and real hardware. Verify time/frame/uncertainty semantics and
   lifecycle cleanup. No unauthorized scans, GNSS signal interference or
   development-host network/location changes; fault injection uses synthetic or
   lawful recorded data and controlled test interfaces, never public RF disruption.
4. Demonstrate independent local relative positioning and, only with validated
   geographic references, absolute positioning without GNSS. Exercise insufficient
   geometry, bad anchors, colluding peers, outages and correlated provenance.
5. Demonstrate hybrid improvement and anomaly handling against separate ground
   truth, with GNSS-only/non-GNSS-only ablations. Report errors, time-to-useful-fix,
   availability, false alerts/missed anomalies, energy, CPU, memory and network
   traffic under the same conditions. Record datasets, hardware, calibration,
   version and reference uncertainty. More peers is not an improvement metric.
6. Verify native Map navigation and selected further application scenarios, private
   grant isolation, no unexpected collection/retention/publication, revocation and
   offline operation. DPS remains unsuitable for certified safety-critical use;
   anomaly detection is not a guarantee against every spoofing or jamming attack.
