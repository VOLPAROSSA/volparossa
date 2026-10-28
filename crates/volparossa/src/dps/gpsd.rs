// SPDX-License-Identifier: GPL-3.0-only
//! Bounded Linux GPSD TPV adapter. GPSD fields and the operator profile remain claims.
//!
//! Uses only the fixed gpspipe client through the operator's PATH. Never starts or
//! signals GPSD, opens a sensor, merges partial TPVs or retains observation history.
//! A private owner task retains the child on caller cancellation and attempts reap
//! within the original deadline. Runtime destruction/kernel stalls cannot establish
//! successful cleanup; no success report is released without an observed child join.

#[cfg(test)]
mod tests;

use std::{
    fmt,
    net::SocketAddrV4,
    os::unix::process::ExitStatusExt,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Timelike};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, BufReader},
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
    sync::watch,
    time::{Instant, timeout_at},
};
use volparossa_local_control::dps::{
    AssessmentLimitation, AssessmentStatus, DPS_SERVICE_VERSION, DpsAssessRequest, FrameKind,
    MAX_DPS_RADIUS_METRES, NavigationAuthentication, PositionFrame, PositionObservation,
    SourceKind,
    geodetic::{HeightReference, Wgs84GeodeticPosition},
};

use super::ProvenanceProfile;

const MAX_LINES: usize = 32;
const MAX_LINE_BYTES: usize = 10_240;
const MAX_TOTAL_BYTES: usize = MAX_LINES * MAX_LINE_BYTES;
const MAX_AGE: Duration = Duration::from_secs(5);
const TOTAL_BUDGET: Duration = Duration::from_secs(10);
const CLEANUP_RESERVE: Duration = Duration::from_secs(2);
// This detects observable wall-clock steps relative to monotonic elapsed time;
// it is neither clock authentication nor a guarantee about smaller clock changes.
const MAX_CLOCK_DIVERGENCE: Duration = Duration::from_millis(250);

type Result<T> = std::result::Result<T, Failure>;

/// Closed diagnostics, without parser/process/OS errors or private input values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Options,
    Spawn,
    Input,
    Bounds,
    Incomplete,
    Device,
    Epoch,
    Geometry,
    Time,
    Clock,
    Randomness,
    Assessment,
    Child,
    Interrupted,
    Deadline,
    CleanupUnconfirmed,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Options => "DPS GPSD options rejected",
            Self::Spawn => "DPS gpspipe unavailable",
            Self::Input => "DPS GPSD frame rejected",
            Self::Bounds => "DPS GPSD input bound exceeded",
            Self::Incomplete => "DPS GPSD complete epochs unavailable",
            Self::Device => "DPS GPSD device binding rejected",
            Self::Epoch => "DPS GPSD epoch ordering rejected",
            Self::Geometry => "DPS GPSD geometry rejected",
            Self::Time => "DPS GPSD receiver time rejected",
            Self::Clock => "DPS GPSD evaluation clock changed",
            Self::Randomness => "DPS source identifiers unavailable",
            Self::Assessment => "DPS assessment unavailable",
            Self::Child => "DPS gpspipe failed",
            Self::Interrupted => "DPS GPSD observation interrupted",
            Self::Deadline => "DPS GPSD observation deadline",
            Self::CleanupUnconfirmed => "DPS gpspipe cleanup unconfirmed",
        })
    }
}

impl std::error::Error for Failure {}

#[derive(Deserialize)]
struct Header {
    class: String,
}

#[derive(Deserialize)]
struct Tpv {
    mode: u8,
    device: Option<String>,
    datum: Option<String>,
    time: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    #[serde(rename = "altHAE")]
    alt_hae: Option<f64>,
}

// Private and deliberately without Debug/Serialize. Only the latest complete
// epoch and one device binding survive inside this single request.
#[derive(PartialEq)]
struct Claim {
    position: Wgs84GeodeticPosition,
    epoch: SystemTime,
}

#[derive(Default)]
struct Epochs {
    device: Option<String>,
    latest: Option<Claim>,
    count: u8,
}

fn receiver_time(value: &str, now: SystemTime) -> Result<SystemTime> {
    if value.len() > 64 {
        return Err(Failure::Time);
    }
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| Failure::Time)?;
    if parsed.nanosecond() >= 1_000_000_000 {
        return Err(Failure::Time);
    }
    let epoch: SystemTime = parsed.into();
    if epoch <= UNIX_EPOCH || now.duration_since(epoch).map_err(|_| Failure::Time)? > MAX_AGE {
        return Err(Failure::Time);
    }
    Ok(epoch)
}

impl Epochs {
    fn push(&mut self, line: &[u8], now: SystemTime) -> Result<bool> {
        let header: Header = serde_json::from_slice(line).map_err(|_| Failure::Input)?;
        if header.class == "ERROR" {
            return Err(Failure::Input);
        }
        if header.class != "TPV" {
            return Ok(false);
        }
        let tpv: Tpv = serde_json::from_slice(line).map_err(|_| Failure::Input)?;
        if tpv.mode > 3 {
            return Err(Failure::Input);
        }
        if let Some(device) = &tpv.device {
            if device.is_empty() || device.len() > 256 || device.chars().any(char::is_control) {
                return Err(Failure::Device);
            }
            if self
                .device
                .as_ref()
                .is_some_and(|binding| binding != device)
            {
                return Err(Failure::Device);
            }
        }
        if tpv.datum.as_deref().is_some_and(|datum| datum != "WGS84") {
            return Err(Failure::Geometry);
        }
        if tpv.datum.is_none() {
            return Ok(false);
        }
        let epoch = tpv
            .time
            .as_deref()
            .map(|value| receiver_time(value, now))
            .transpose()?;
        // Missing fields are not borrowed from any earlier TPV. altMSL and error
        // estimates are ignored, never converted to altHAE or confidence claims.
        let (Some(device), Some(epoch), Some(lat), Some(lon), Some(height)) =
            (tpv.device, epoch, tpv.lat, tpv.lon, tpv.alt_hae)
        else {
            return Ok(false);
        };
        if tpv.mode != 3 {
            return Ok(false);
        }
        let position = Wgs84GeodeticPosition {
            latitude_degrees: lat,
            longitude_degrees: lon,
            height_metres: height,
            height_reference: HeightReference::Wgs84Ellipsoid,
        };
        position.to_ecef().map_err(|_| Failure::Geometry)?;
        let claim = Claim { position, epoch };
        if let Some(previous) = &self.latest {
            if claim.epoch < previous.epoch {
                return Err(Failure::Epoch);
            }
            if claim.epoch == previous.epoch {
                return if claim == *previous {
                    Ok(false)
                } else {
                    Err(Failure::Epoch)
                };
            }
        }
        self.device = Some(device);
        self.latest = Some(claim);
        self.count += 1;
        Ok(self.count == 3)
    }
}

struct Clock {
    wall: SystemTime,
    monotonic: Instant,
    last_wall: SystemTime,
}

impl Clock {
    fn new() -> Self {
        let wall = SystemTime::now();
        Self {
            wall,
            monotonic: Instant::now(),
            last_wall: wall,
        }
    }

    fn sample(&mut self) -> Result<SystemTime> {
        self.check(SystemTime::now(), Instant::now())
    }

    fn check(&mut self, wall: SystemTime, monotonic: Instant) -> Result<SystemTime> {
        if wall < self.last_wall {
            return Err(Failure::Clock);
        }
        let wall_elapsed = wall.duration_since(self.wall).map_err(|_| Failure::Clock)?;
        let elapsed = monotonic
            .checked_duration_since(self.monotonic)
            .ok_or(Failure::Clock)?;
        if wall_elapsed.abs_diff(elapsed) > MAX_CLOCK_DIVERGENCE {
            return Err(Failure::Clock);
        }
        self.last_wall = wall;
        Ok(wall)
    }
}

async fn bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    total: &mut usize,
) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|_| Failure::Input)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(Failure::Input)
            };
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len() + count > MAX_LINE_BYTES || *total + count > MAX_TOTAL_BYTES {
            return Err(Failure::Bounds);
        }
        let complete = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        *total += count;
        reader.consume(count);
        if complete {
            return Ok(Some(line));
        }
    }
}

async fn collect<R: AsyncBufRead + Unpin>(mut reader: R, clock: &mut Clock) -> Result<Claim> {
    let mut epochs = Epochs::default();
    let mut total = 0;
    for _ in 0..MAX_LINES {
        let line = bounded_line(&mut reader, &mut total)
            .await?
            .ok_or(Failure::Incomplete)?;
        if epochs.push(&line, clock.sample()?)? {
            return epochs.latest.ok_or(Failure::Incomplete);
        }
    }
    Err(Failure::Bounds)
}

fn options(endpoint: SocketAddrV4, radius: f64) -> Result<()> {
    if !endpoint.ip().is_loopback()
        || endpoint.port() <= 1024
        || !radius.is_finite()
        || !(1.0..=MAX_DPS_RADIUS_METRES).contains(&radius)
    {
        return Err(Failure::Options);
    }
    Ok(())
}

fn gpspipe(endpoint: SocketAddrV4) -> Result<Command> {
    let mut command = Command::new("gpspipe");
    command
        .args(["-w", "-B", "-n", "32", "-x", "8", &endpoint.to_string()])
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let path = std::env::var_os("PATH")
        .filter(|path| !path.is_empty())
        .ok_or(Failure::Options)?;
    command.env("PATH", path);
    Ok(command)
}

async fn finish_child(child: &mut Child, deadline: Instant) -> Result<()> {
    if let Some(status) = child.try_wait().map_err(|_| Failure::CleanupUnconfirmed)? {
        return if status.success() {
            Ok(())
        } else {
            Err(Failure::Child)
        };
    }
    child
        .start_kill()
        .map_err(|_| Failure::CleanupUnconfirmed)?;
    let status = timeout_at(deadline, child.wait())
        .await
        .map_err(|_| Failure::CleanupUnconfirmed)?
        .map_err(|_| Failure::CleanupUnconfirmed)?;
    if status.success() || status.signal() == Some(libc::SIGKILL) {
        Ok(())
    } else {
        Err(Failure::Child)
    }
}

async fn own_child(
    mut child: Child,
    mut cancel: watch::Receiver<bool>,
    deadline: Instant,
    radius: f64,
) -> Result<Quality> {
    let mut clock = Clock::new();
    let stdout = child.stdout.take();
    let result = if let Some(stdout) = stdout {
        tokio::select! {
            biased;
            _ = cancel.wait_for(|cancelled| *cancelled) => Err(Failure::Interrupted),
            result = timeout_at(deadline - CLEANUP_RESERVE, collect(BufReader::with_capacity(1024, stdout), &mut clock)) =>
                result.map_err(|_| Failure::Deadline).and_then(|result| result),
        }
    } else {
        Err(Failure::Input)
    };
    let joined = finish_child(&mut child, deadline).await;
    if joined == Err(Failure::CleanupUnconfirmed) {
        return Err(Failure::CleanupUnconfirmed);
    }
    let claim = result?;
    joined?;
    let result = assessment(&claim, radius, clock.sample()?);
    if Instant::now() >= deadline {
        return Err(Failure::Deadline);
    }
    result
}

struct Cancel(watch::Sender<bool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

pub(super) async fn observe(
    endpoint: SocketAddrV4,
    _profile: ProvenanceProfile,
    radius: f64,
) -> Result<Quality> {
    options(endpoint, radius)?;
    let deadline = Instant::now() + TOTAL_BUDGET;
    // Register before spawning so the explicit command can always reap its child
    // on INT/TERM/HUP. Tokio's process-wide signal handler lives until CLI exit.
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| Failure::Spawn)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| Failure::Spawn)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|_| Failure::Spawn)?;
    let (sender, receiver) = watch::channel(false);
    let cancel = Cancel(sender);
    let mut owner = tokio::spawn(async move {
        if *receiver.borrow() {
            return Err(Failure::Interrupted);
        }
        let child = gpspipe(endpoint)?.spawn().map_err(|_| Failure::Spawn)?;
        own_child(child, receiver, deadline, radius).await
    });
    tokio::select! {
        result = &mut owner => result.map_err(|_| Failure::CleanupUnconfirmed)?,
        _ = async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = hangup.recv() => {} } } => {
            let _ = cancel.0.send(true);
            let result = owner.await.map_err(|_| Failure::CleanupUnconfirmed)?;
            if matches!(result, Err(Failure::CleanupUnconfirmed)) { return Err(Failure::CleanupUnconfirmed); }
            Err(Failure::Interrupted)
        }
    }
}

#[derive(Serialize)]
pub(super) struct Quality {
    schema_version: u32,
    quality: &'static str,
    candidate_present: bool,
    declared_independence_groups: u32,
    eligible_claims: usize,
    limitations: Vec<&'static str>,
    provenance: Provenance,
}

#[derive(Serialize)]
struct Provenance {
    input: &'static str,
    profile: &'static str,
    complete_distinct_epochs: u8,
    physical_datum_verified: bool,
    uncertainty_confidence: &'static str,
    navigation_authentication: &'static str,
}

fn assessment(claim: &Claim, radius: f64, now: SystemTime) -> Result<Quality> {
    if now.duration_since(claim.epoch).map_err(|_| Failure::Time)? > MAX_AGE {
        return Err(Failure::Time);
    }
    let request = request_for(claim, radius)?;
    let result = request
        .assess(unix_millis(now)?)
        .map_err(|_| Failure::Assessment)?;
    result.validate().map_err(|_| Failure::Assessment)?;
    if result.status != AssessmentStatus::SingleClaim as i32
        || result.unverified_input_position.is_none()
        || result.observations.len() != 1
        || result.declared_independence_groups != 1
    {
        return Err(Failure::Assessment);
    }
    let limitations = result
        .limitations
        .into_iter()
        .map(limitation)
        .collect::<Result<Vec<_>>>()?;
    Ok(Quality {
        schema_version: 1,
        quality: "SingleClaim",
        candidate_present: true,
        declared_independence_groups: 1,
        eligible_claims: 1,
        limitations,
        provenance: Provenance {
            input: "gpsd_tpv",
            profile: "operator_asserted_wgs84_receiver_ellipsoidal",
            complete_distinct_epochs: 3,
            physical_datum_verified: false,
            uncertainty_confidence: "unknown",
            navigation_authentication: "unknown",
        },
    })
}

fn unix_millis(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(Failure::Time)
}

fn request_for(claim: &Claim, radius: f64) -> Result<DpsAssessRequest> {
    let [x, y, z] = claim
        .position
        .to_ecef()
        .map_err(|_| Failure::Geometry)?
        .components_metres();
    let mut identifiers = [[0; 16]; 3];
    for id in &mut identifiers {
        getrandom::fill(id).map_err(|_| Failure::Randomness)?;
    }
    let frame = PositionFrame {
        kind: FrameKind::Wgs84Ecef as i32,
        local_frame_id: vec![],
    };
    Ok(DpsAssessRequest {
        dps_version: DPS_SERVICE_VERSION,
        desired_frame: Some(frame.clone()),
        maximum_age_ms: 5000,
        observations: vec![PositionObservation {
            observation_id: identifiers[0].to_vec(),
            source_id: identifiers[1].to_vec(),
            declared_independence_group: identifiers[2].to_vec(),
            source_kind: SourceKind::Gnss as i32,
            frame: Some(frame),
            x_metres: x,
            y_metres: y,
            z_metres: z,
            supplied_radius_metres: radius,
            observed_at_unix_ms: unix_millis(claim.epoch)?,
            navigation_authentication: NavigationAuthentication::Unknown as i32,
        }],
    })
}

fn limitation(value: i32) -> Result<&'static str> {
    Ok(
        match AssessmentLimitation::try_from(value).map_err(|_| Failure::Assessment)? {
            AssessmentLimitation::CallerSuppliedEvidence => "CallerSuppliedEvidence",
            AssessmentLimitation::PhysicalIntegrityUnverified => "PhysicalIntegrityUnverified",
            AssessmentLimitation::PhysicalIndependenceUnverified => {
                "PhysicalIndependenceUnverified"
            }
            AssessmentLimitation::UncertaintyConfidenceUnknown => "UncertaintyConfidenceUnknown",
            AssessmentLimitation::NoSensorFusion => "NoSensorFusion",
            AssessmentLimitation::NoSensorOrClockVerification => "NoSensorOrClockVerification",
            AssessmentLimitation::PairwiseConsistencyOnly => "PairwiseConsistencyOnly",
        },
    )
}
