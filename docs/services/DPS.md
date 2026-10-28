# Decentralized Positioning System

[Service status](../IMPLEMENTATION_STATUS.md) records current cross-service priorities.
Detailed superseded trial narratives are retained in the
[service evidence archive](../archive/service-notes-20261026.txt); they are not startup instructions.

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

The bounded normal-daemon proof covers a dormant launch, synthetic framed request,
joined shutdown and owned socket/fixture removal. It establishes neither app-facing
location authority, full crash/restart cleanup nor sensor/fusion accuracy; source-bound
results are in [implementation status](../IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21).

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
geographic anchor. The bounded forward conversion below supplies ECEF input;
vertical datum conversion and anchor validation remain separate work. Never compare
unrelated local origins, epochs or altitude datums as one frame.

`dps::geodetic::Wgs84GeodeticPosition` converts explicitly supplied latitude and
longitude in degrees plus WGS84 ellipsoidal height in metres into ECEF metres.
The caller must select `HeightReference::Wgs84Ellipsoid`; unknown and mean-sea-level
heights are rejected because no geoid model is supplied. Non-finite values,
out-of-range angles and output exceeding the existing component bound fail closed.
Debug and error output omit coordinates. The existing synthetic example and daemon
fixture use this same converter; their positions and assessment scope are unchanged.

The calculation uses the [NGA WGS84 ellipsoid parameters](https://earth-info.nga.mil/index.php?action=wgs84&dir=wgs84)
and the forward EPSG 9602 formula in
[IOGP Guidance Note 7-2, September 2019, section 4.1.1](https://www.iogp.org/wp-content/uploads/2019/09/373-07-02.pdf).
Reference-vector agreement tests numerical conversion, not physical positioning
accuracy. This helper verifies no datum, realization, epoch, sensor, uncertainty,
clock or application permission, and performs no datum transformation or sensor
fusion. It acquires no data, stores no history and changes no wire or native ABI.

### Explicit local GPSD observation

On Linux, an operator may explicitly request one local observation with
`volparossa dps observe-gpsd --endpoint 127.0.0.1:2947 --profile wgs84-receiver-ellipsoidal --comparison-radius-metres 10`.
This uses an already available official `gpspipe` client from the operator's PATH;
it starts no GPSD service and changes no roles, device permissions or host settings.
The endpoint must be numeric IPv4 loopback with a port above 1024. The command
neither uses the administrative agent socket nor publishes or retains a position.

The adapter requires three distinct, increasing, complete TPV epochs from one
device, each declaring `WGS84`, mode 3, latitude, longitude and `altHAE`. Partial
messages are never merged. Mean-sea-level height cannot substitute for missing
ellipsoidal height. The explicit profile asserts receiver provenance; a JSON datum
or height field does not independently verify its physical meaning. Receiver time
must be no more than five seconds old and cannot be in the future. Observable
backward wall-clock steps and wall/monotonic divergence over 250 ms are rejected;
this is not authenticated time. Input is bounded to 32 lines of 10,240 bytes each,
with eight seconds for collection inside a ten-second operation/cleanup budget.

Only the latest complete fix reaches the existing in-process assessor, as one
request-local GNSS claim with unknown navigation authentication and unknown radius
confidence. Output contains `SingleClaim` quality, the seven existing limitations
and closed provenance fields; it omits coordinates, receiver timestamps, device
paths and source identifiers. A success requires the owned `gpspipe` child to have
been joined. Runtime destruction or an unresponsive kernel cannot prove cleanup.
This provides no sensor fusion, spoofing assurance or physical accuracy guarantee.

The opt-in `gpsd-adapter` route in `dps-native-quality.yml` builds fixed GPSD
sources with the full Debian security patch series, then exercises public synthetic
NMEA through real `gpsfake`, PTY, `gpsd`, `gpspipe` and this CLI. Upstream checks
and AddressSanitizer/UndefinedBehaviorSanitizer execution run only inside disposable
network, IPC and PID namespaces. Its [source and proof contract](../../tests/dps/gpsd/README.md)
is separate from historical native ABI evidence, physical receiver acceptance,
Debian 13 runtime acceptance and app-facing permission/lifecycle integration.

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
forwarding path. At that plan snapshot, native Rust linkage/coordinator work was still absent;
its Python component was not an Android bridge. Later bounded JNI evidence is
separate from genuine sensor/navigation integration.

### Quality-only native ABI

The shared Rust assessor exposes a 36-byte response containing exactly nine `u32`
quality/limitation fields. Canonical bare-protobuf requests are bounded to 16 KiB.
No coordinates or fix are returned; the library acquires no sensors, keeps no
history and accesses no administrative socket. Keep Rust assessment as the single
algorithm: the Map adapter cannot turn relative/unavailable quality into a GPS fix.
C/C++ caller, sanitizer and Valgrind trials cover their recorded source and scope;
the Rust library itself was not sanitizer-instrumented.

The bounded Map debug path uses an app-owned coordinator and C/JNI bridge without
loading the Organic Maps framework or requesting location. Link its standalone
native target to the Rust static library and required Android system libraries,
not the existing Organic Maps JNI helper or `JNI_OnLoad`. Keep work outside the
real location helper, GPS listeners and track route; a JNI lifecycle is not proof
of OS app identity or location authorization.

Before work and again before publication, check app-owned consent generation,
monotonic expiry and active lifecycle. Revocation, disable or backgrounding clears
selected DPS state and invalidates pending results; late completions cannot
republish it. Cancel and join owned work. Synthetic denied-location fixtures must
exercise displayed quality, expiry, revocation during work, background/resume,
late-result rejection, unavailable offline input and absence of sensor/network activity.

<a id="historical-map-checkpoint"></a>
<a id="current-map-checkpoint--2026-10-22"></a>
<a id="earlier-map-checkpoint--2026-10-21"></a>

The [current recorded Map checkpoint](../IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21)
accepts a bounded completed-emulator debug/JNI slice while retaining its raw host
comparison failure. Earlier KVM, instrumentation and cleanup failures remain in the
[dated evidence archive](../archive/service-notes-20261026.txt); no timestamp
normalization or retrospective pass follows. Real sensor acquisition, frame
conversion, precision authorization, independent GNSS integrity and native
navigation remain subsequent work.

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
